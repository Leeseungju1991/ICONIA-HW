// =============================================================================
// iconia_upload_queue — 업로드 실패 이벤트 영속 큐 (events_queue partition)
// -----------------------------------------------------------------------------
// 본 모듈은 카메라 capture + 메타데이터 봉투를 SPIFFS partition `events_q` 에
// 영속 저장하고, 다음 부팅 또는 다음 wake 시 우선 flush 하는 책임만 진다.
//
// 정합 책임
//   - event_id (멱등 키) 는 이미 iconia_app.cpp::buildEventId 가 emit. 본 큐는
//     그 값을 그대로 보존. 서버 idempotencyCache 와 1:1 정합 (24h dedup window).
//   - 큐 max size 는 partition 크기로 제약. 본 라운드 layout: 0xB0000 = 704 KB.
//     단일 entry 평균 ~120 KB (VGA JPEG q12 + 메타) → 5~6 entry 보존.
//   - 초과 시 가장 오래된 entry drop (FIFO 방식). drop 횟수는 telemetry counter
//     (RTC slow-mem) 로 누적, 다음 성공 업로드에 동봉.
//
// 정본: docs/operational_telemetry.md §2 (업로드 실패 카테고리 + 큐 정책)
//
// 비-목표
//   - 본 모듈은 보안/암호화를 적용하지 않는다. SPIFFS 자체는 flash encryption
//     활성화 시 자동 암호화되며, 본 라운드는 prod build 가 항상 lockdown 모드
//     (= flash encryption 강제) 이므로 이중 암호화는 불필요.
//   - 본 모듈은 HTTP 전송을 직접 수행하지 않는다. 호출자가 dequeue 후 기존
//     postEventMultipart 경로로 전송, 결과에 따라 ack(deleteCurrent) / 다시
//     선두 보존(retainHead).
// =============================================================================

#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>

namespace iconia {
namespace upload_queue {

// partitions.csv 의 events_q 파티션 라벨. 본 상수와 정확히 일치해야 한다.
static constexpr const char* kPartitionLabel = "events_q";

// SPIFFS 마운트 포인트. 외부 관측에 노출되지 않으며 본 모듈만 사용.
static constexpr const char* kMountPoint = "/eq";

// 단일 entry 의 메타 헤더 (이미지 파일과 1:1 페어).
struct EntryMeta {
  char     eventId[40];       // iconia_app.cpp 가 생성한 멱등 키
  char     touch[8];          // "left" / "right" / "none"
  int      batteryPercent;    // 0..100
  uint32_t firstAttemptMs;    // 첫 시도 시각 (millis 기반 단조)
  uint8_t  attemptNo;         // 현재까지 누적 시도 횟수 (1 부터)
  uint16_t failureCategory;   // docs/operational_telemetry.md §2.2 코드
  int16_t  wifiRssiDbm;       // 가장 최근 시도의 RSSI (없으면 0)
  uint16_t batteryMv;         // 가장 최근 시도의 배터리 mV (없으면 0)
};

// 큐 상태 메타 (RTC slow-mem 보존). 초과 drop 카운터 등 telemetry.
struct QueueStats {
  uint32_t totalEnqueued;     // 누적 enqueue 횟수 (초기화 후)
  uint32_t totalDroppedFull;  // 큐 가득 차 drop 된 횟수 (가장 오래된 entry)
  uint32_t totalFlushedOk;    // 큐에서 정상 dequeue + 서버 200 OK 횟수
};

// 부팅 시 1회 호출. SPIFFS 마운트 시도 + 실패 시 자동 format.
// 반환: true = 마운트 성공 (큐 사용 가능). false = 디스크 자체 불가 (큐 비활성).
bool begin();

// 큐가 비어있는지.
bool empty();

// 새 entry 를 큐 tail 에 enqueue. 큐가 가득 차면 가장 오래된 entry 부터 drop.
// imageData / imageLen 은 즉시 SPIFFS 에 write 후 반환 (호출자는 frame buffer
// 를 release 가능).
//
// 반환: true = 저장 성공. false = 디스크 오류 (이번 wake 는 buffer in-RAM 으로
// 흘려보내고 큐 보존을 포기, 다음 wake 부터 다시 시도).
bool enqueue(const EntryMeta& meta,
             const uint8_t* imageData, size_t imageLen);

// 큐 head entry 의 메타 + 이미지 핸들을 읽어 호출자에게 노출.
// 이미지는 내부 임시 버퍼(PSRAM) 로 한 번에 로드 — VGA JPEG 100~200 KB 수준이라
// PSRAM 4 MB 모듈에서 안전. 호출자가 사용 후 releaseHead() 호출 필수.
//
// 반환: nullptr = 큐 비어있거나 read 실패.
struct PeekedHead {
  EntryMeta     meta;
  const uint8_t* imageData;
  size_t        imageLen;
};
const PeekedHead* peekHead();
void releaseHead();

// peek 한 entry 를 큐에서 영구 삭제. 서버 200 OK 확인 후 호출.
bool deleteHead();

// peek 한 entry 의 attempt_no/failure_category/rssi/battery 를 갱신해 큐에 다시
// 남긴다 (head 위치 유지). 다음 wake 가 같은 entry 를 또 시도.
bool updateHeadAfterFailure(uint16_t failureCategory,
                            int16_t wifiRssiDbm,
                            uint16_t batteryMv);

// 큐 통계 조회. RTC slow-mem 의 카운터를 그대로 반환.
QueueStats stats();

// 통계 카운터를 명시적 zero-fill (factory reset 등 운영 시점에 사용).
// 일반 흐름에서는 호출하지 않음.
void resetStats();

}  // namespace upload_queue
}  // namespace iconia
