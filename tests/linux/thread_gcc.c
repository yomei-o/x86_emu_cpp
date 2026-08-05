// pthreads: mutex-guarded counter across 4 threads, then join.
#include <pthread.h>
#include <stdio.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long counter = 0;

static void* worker(void* arg) {
    for (int i = 0; i < 10000; ++i) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return (void*)(long)(*(int*)arg);
}

int main(void) {
    pthread_t t[4];
    int ids[4] = {1, 2, 3, 4};
    for (int i = 0; i < 4; ++i) pthread_create(&t[i], NULL, worker, &ids[i]);
    long sum = 0;
    for (int i = 0; i < 4; ++i) {
        void* r = NULL;
        pthread_join(t[i], &r);
        sum += (long)r;
    }
    printf("counter=%ld retsum=%ld\n", counter, sum);
    return 0;
}
