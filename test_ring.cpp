#include "mpsc_ring_buffer.h"
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>

static constexpr int kProducers = 4;
static constexpr int kItemsPerProducer = 100000;

int main() {
    MpscRingBuffer<8192> ring;

    std::atomic<int> total_pushed{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&, p] {
            for (int i = 0; i < kItemsPerProducer; ++i) {
                auto* desc = new IovecDescriptor(nullptr, p * kItemsPerProducer + i);
                while (!ring.push(desc)) { /* spin */ }
                total_pushed.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    int consumed = 0;
    const int expect = kProducers * kItemsPerProducer;
    while (consumed < expect) {
        IovecDescriptor* out = nullptr;
        if (ring.pop(out)) {
            assert(out->ref_count.load() == 2);
            delete out;
            ++consumed;
        }
    }

    for (auto& t : producers) t.join();
    assert(consumed == expect);
    assert(total_pushed.load() == expect);

    std::printf("PASS: %d items transferred via %d producers\n", consumed, kProducers);
    return 0;
}
