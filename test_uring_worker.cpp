#include "uring_worker.h"
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main()
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::perror("socket");
        return 1;
    }

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(9999);
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    UringWorker worker(fd, dest);
    UringWorker::Queue queue;

    char buf[] = "hello zerocopy";
    struct iovec v{ .iov_base = buf, .iov_len = sizeof(buf) };
    auto* desc = new IovecDescriptor(&v, 1);
    queue.push(desc);

    worker.start_loop(&queue);
    usleep(100'000);
    worker.request_stop();

    close(fd);
    std::printf("LINK OK: UringWorker compiled and ran successfully\n");
    return 0;
}
