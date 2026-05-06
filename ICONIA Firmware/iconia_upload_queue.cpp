// =============================================================================
// iconia_upload_queue — implementation (SPIFFS-backed FIFO)
// 정본: docs/operational_telemetry.md §2
// -----------------------------------------------------------------------------
// 큐 레이아웃
//   /eq/idx                (text, 8 bytes "head=NN tail=NN")
//   /eq/<NN>.meta          (binary, sizeof(EntryMeta))
//   /eq/<NN>.jpg           (binary, JPEG raw bytes)
// NN 은 0..kSlotCount-1 의 ring index. head==tail 이면 비어있음.
// kSlotCount=8 — 메타+이미지 한 슬롯이 ~120 KB 이므로 8 슬롯 = ~1 MB 한도.
// 단, 본 partition 은 0xB0000 (704 KB) 이므로 SPIFFS 가 자동으로 잔여 슬롯에
// write 거부 → enqueue 가 실패하면 호출자가 가장 오래된 슬롯 drop 후 retry.
// =============================================================================

#include "iconia_upload_queue.h"

#include <SPIFFS.h>
#include <FS.h>
#include "esp_attr.h"
#include "esp_heap_caps.h"

namespace iconia {
namespace upload_queue {

static constexpr uint8_t kSlotCount = 8;

// RTC slow-mem 카운터.
RTC_DATA_ATTR static QueueStats s_stats = {0, 0, 0};

// 마운트 상태 / head-tail 인덱스 (RAM 상태, 부팅 시 idx 파일에서 복원).
static bool     s_mounted   = false;
static uint8_t  s_head      = 0;
static uint8_t  s_tail      = 0;

// peekHead 가 채우는 버퍼 (PSRAM heap). releaseHead 에서 free.
static uint8_t*    s_peekImageBuf = nullptr;
static size_t      s_peekImageLen = 0;
static PeekedHead  s_peekHead     = {};
static bool        s_peekValid    = false;

static String slotMetaPath(uint8_t idx) {
  String s(kMountPoint);
  s += "/";
  s += idx;
  s += ".meta";
  return s;
}
static String slotImagePath(uint8_t idx) {
  String s(kMountPoint);
  s += "/";
  s += idx;
  s += ".jpg";
  return s;
}
static String idxPath() {
  return String(kMountPoint) + "/idx";
}

static void writeIdx() {
  File f = SPIFFS.open(idxPath(), FILE_WRITE);
  if (!f) return;
  f.printf("head=%u tail=%u\n", (unsigned)s_head, (unsigned)s_tail);
  f.close();
}
static void readIdx() {
  File f = SPIFFS.open(idxPath(), FILE_READ);
  if (!f) {
    s_head = 0;
    s_tail = 0;
    return;
  }
  String line = f.readStringUntil('\n');
  f.close();
  unsigned h = 0, t = 0;
  if (sscanf(line.c_str(), "head=%u tail=%u", &h, &t) == 2 &&
      h < kSlotCount && t < kSlotCount) {
    s_head = (uint8_t)h;
    s_tail = (uint8_t)t;
  } else {
    s_head = 0;
    s_tail = 0;
  }
}

bool begin() {
  if (s_mounted) return true;
  // events_q partition 라벨로 SPIFFS mount. format-on-fail = true 로 자동 복구.
  if (!SPIFFS.begin(true, kMountPoint, 5, kPartitionLabel)) {
    s_mounted = false;
    return false;
  }
  s_mounted = true;
  readIdx();
  return true;
}

bool empty() {
  if (!s_mounted) return true;
  return s_head == s_tail;
}

static uint8_t nextIdx(uint8_t i) { return (uint8_t)((i + 1) % kSlotCount); }
static bool isFull() { return nextIdx(s_tail) == s_head; }

static bool dropOldest() {
  if (empty()) return false;
  SPIFFS.remove(slotMetaPath(s_head));
  SPIFFS.remove(slotImagePath(s_head));
  s_head = nextIdx(s_head);
  s_stats.totalDroppedFull++;
  writeIdx();
  return true;
}

bool enqueue(const EntryMeta& meta,
             const uint8_t* imageData, size_t imageLen) {
  if (!s_mounted) return false;
  // 가득 차면 가장 오래된 entry drop.
  if (isFull()) {
    dropOldest();
  }
  uint8_t slot = s_tail;
  // meta write
  {
    File f = SPIFFS.open(slotMetaPath(slot), FILE_WRITE);
    if (!f) return false;
    size_t w = f.write(reinterpret_cast<const uint8_t*>(&meta), sizeof(EntryMeta));
    f.close();
    if (w != sizeof(EntryMeta)) {
      SPIFFS.remove(slotMetaPath(slot));
      return false;
    }
  }
  // image write
  {
    File f = SPIFFS.open(slotImagePath(slot), FILE_WRITE);
    if (!f) {
      SPIFFS.remove(slotMetaPath(slot));
      return false;
    }
    size_t w = f.write(imageData, imageLen);
    f.close();
    if (w != imageLen) {
      SPIFFS.remove(slotMetaPath(slot));
      SPIFFS.remove(slotImagePath(slot));
      return false;
    }
  }
  s_tail = nextIdx(s_tail);
  s_stats.totalEnqueued++;
  writeIdx();
  return true;
}

const PeekedHead* peekHead() {
  if (s_peekValid) {
    return &s_peekHead;
  }
  if (!s_mounted || empty()) {
    return nullptr;
  }
  uint8_t slot = s_head;
  // meta load
  {
    File f = SPIFFS.open(slotMetaPath(slot), FILE_READ);
    if (!f) return nullptr;
    size_t r = f.read(reinterpret_cast<uint8_t*>(&s_peekHead.meta), sizeof(EntryMeta));
    f.close();
    if (r != sizeof(EntryMeta)) return nullptr;
  }
  // image load (PSRAM)
  {
    File f = SPIFFS.open(slotImagePath(slot), FILE_READ);
    if (!f) return nullptr;
    size_t imgLen = f.size();
    if (imgLen == 0) {
      f.close();
      return nullptr;
    }
    s_peekImageBuf = (uint8_t*)heap_caps_malloc(imgLen, MALLOC_CAP_SPIRAM);
    if (s_peekImageBuf == nullptr) {
      f.close();
      return nullptr;
    }
    size_t r = f.read(s_peekImageBuf, imgLen);
    f.close();
    if (r != imgLen) {
      heap_caps_free(s_peekImageBuf);
      s_peekImageBuf = nullptr;
      return nullptr;
    }
    s_peekImageLen = imgLen;
  }
  s_peekHead.imageData = s_peekImageBuf;
  s_peekHead.imageLen = s_peekImageLen;
  s_peekValid = true;
  return &s_peekHead;
}

void releaseHead() {
  if (s_peekImageBuf != nullptr) {
    heap_caps_free(s_peekImageBuf);
    s_peekImageBuf = nullptr;
  }
  s_peekImageLen = 0;
  s_peekValid = false;
}

bool deleteHead() {
  if (!s_mounted || empty()) return false;
  releaseHead();
  SPIFFS.remove(slotMetaPath(s_head));
  SPIFFS.remove(slotImagePath(s_head));
  s_head = nextIdx(s_head);
  s_stats.totalFlushedOk++;
  writeIdx();
  return true;
}

bool updateHeadAfterFailure(uint16_t failureCategory,
                            int16_t wifiRssiDbm,
                            uint16_t batteryMv) {
  if (!s_mounted || empty()) return false;
  EntryMeta meta = {};
  uint8_t slot = s_head;
  {
    File f = SPIFFS.open(slotMetaPath(slot), FILE_READ);
    if (!f) return false;
    size_t r = f.read(reinterpret_cast<uint8_t*>(&meta), sizeof(EntryMeta));
    f.close();
    if (r != sizeof(EntryMeta)) return false;
  }
  if (meta.attemptNo < 0xFF) meta.attemptNo++;
  meta.failureCategory = failureCategory;
  meta.wifiRssiDbm = wifiRssiDbm;
  meta.batteryMv = batteryMv;
  {
    File f = SPIFFS.open(slotMetaPath(slot), FILE_WRITE);
    if (!f) return false;
    size_t w = f.write(reinterpret_cast<const uint8_t*>(&meta), sizeof(EntryMeta));
    f.close();
    if (w != sizeof(EntryMeta)) return false;
  }
  releaseHead();  // 캐시 무효화 — 다음 peek 가 새 메타를 읽도록
  return true;
}

QueueStats stats() { return s_stats; }
void resetStats() { s_stats = {0, 0, 0}; }

}  // namespace upload_queue
}  // namespace iconia
