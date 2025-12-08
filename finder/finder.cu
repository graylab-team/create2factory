#if defined(_WIN64)
    #define WIN32_NO_STATUS
    #include <windows.h>
    #undef WIN32_NO_STATUS
#endif

#include <thread>
#include <cinttypes>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <queue>
#include <chrono>
#include <fstream>
#include <vector>

#include "secure_rand.h"
#include "structures.h"

#include "cpu_curve_math.h"
#include "cpu_keccak.h"
#include "cpu_math.h"

#define OUTPUT_BUFFER_SIZE 10000

#define BLOCK_SIZE 256U
#define THREAD_WORK (1U << 8)

__constant__ CurvePoint thread_offsets[BLOCK_SIZE];
__constant__ CurvePoint addends[THREAD_WORK - 1];
__device__ uint64_t device_memory[2 + OUTPUT_BUFFER_SIZE * 3];

__device__ int scoring(Address a) {
    int n = __clz(a.a);
    if (n == 32) {
        n += __clz(a.b);
        if (n == 64) {
            n += __clz(a.c);
            if (n == 96) {
                n += __clz(a.d);
                if (n == 128) {
                    n += __clz(a.e);
                }
            }
        }
    }
    return n >> 2;
}

#ifdef __linux__
    #define atomicMax_ul(a, b) atomicMax((unsigned long long*)(a), (unsigned long long)(b))
    #define atomicAdd_ul(a, b) atomicAdd((unsigned long long*)(a), (unsigned long long)(b))
#else
    #define atomicMax_ul(a, b) atomicMax(a, b)
    #define atomicAdd_ul(a, b) atomicAdd(a, b)
#endif

__device__ void handle_output(int score, Address a, uint64_t key, bool inv) {
    int _score = scoring(a);
    if (_score >= score) {
        uint32_t idx = atomicAdd_ul(&device_memory[0], 1);
        if (idx < OUTPUT_BUFFER_SIZE) {
            device_memory[2 + idx] = key;
            device_memory[OUTPUT_BUFFER_SIZE + 2 + idx] = _score;
            device_memory[OUTPUT_BUFFER_SIZE * 2 + 2 + idx] = inv;
        }
    }
}

__device__ void handle_output2(int score, Address a, uint64_t key) {
    int _score = scoring(a);
    if (_score >= score) {
        uint32_t idx = atomicAdd_ul(&device_memory[0], 1);
        if (idx < OUTPUT_BUFFER_SIZE) {
            device_memory[2 + idx] = key;
            device_memory[OUTPUT_BUFFER_SIZE + 2 + idx] = _score;
        }
    }
}

#include "address.h"

__device__ _uint256 bind_salt(_uint256 salt, Address deployer) {
        uint64_t block[25];
        for (int i = 0; i < 25; i++) {
            block[i] = 0;
        }
    
        block[0] = swap_endianness(((uint64_t)salt.a << 32) | (uint64_t)salt.b);
        block[5] = swap_endianness(((uint64_t)salt.c << 32) | (uint64_t)salt.d);
        block[10] = swap_endianness(((uint64_t)salt.e << 32) | (uint64_t)salt.f);
        block[15] = swap_endianness(((uint64_t)salt.g << 32) | (uint64_t)salt.h);
    
        block[20] = swap_endianness(0x0000000000000000ULL);
        block[1] = swap_endianness(((uint64_t)deployer.a));
        block[6] = swap_endianness(((uint64_t)deployer.b << 32) | (uint64_t)deployer.c);
        block[11] = swap_endianness(((uint64_t)deployer.d << 32) | (uint64_t)deployer.e);
    
        block[16] = swap_endianness(0x0100000000000000ULL);
        block[8] = 0x8000000000000000ULL;
    
        block_permute(block);
    
        uint64_t a_out = swap_endianness(block[0]);
        uint64_t b_out = swap_endianness(block[5]);
        uint64_t c_out = swap_endianness(block[10]);
        uint64_t d_out = swap_endianness(block[15]);
    
        return {(uint32_t)(a_out >> 32), (uint32_t)(a_out & 0xFFFFFFFF),
                (uint32_t)(b_out >> 32), (uint32_t)(b_out & 0xFFFFFFFF),
                (uint32_t)(c_out >> 32), (uint32_t)(c_out & 0xFFFFFFFF),
                (uint32_t)(d_out >> 32), (uint32_t)(d_out & 0xFFFFFFFF)};
    }
    

__device__ Address calculate_contract_address2(Address a, Address bb, _uint256 salt, _uint256 bytecode) {
    salt = bind_salt(salt, bb);
    uint64_t block[25];
    for (int i = 0; i < 25; i++) {
        block[i] = 0;
    }

    block[0] = swap_endianness((0xFFULL << 56) | ((uint64_t)a.a << 24) | (a.b >> 8));
    block[5] = swap_endianness(((uint64_t)a.b << 56) | ((uint64_t)a.c << 24) | (a.d >> 8));
    block[10] = swap_endianness(((uint64_t)a.d << 56) | ((uint64_t)a.e << 24) | (salt.a >> 8));
    block[15] = swap_endianness(((uint64_t)salt.a << 56) | ((uint64_t)salt.b << 24) | (salt.c >> 8));
    block[20] = swap_endianness(((uint64_t)salt.c << 56) | ((uint64_t)salt.d << 24) | (salt.e >> 8));
    block[1] = swap_endianness(((uint64_t)salt.e << 56) | ((uint64_t)salt.f << 24) | (salt.g >> 8));
    block[6] = swap_endianness(((uint64_t)salt.g << 56) | ((uint64_t)salt.h << 24) | (bytecode.a >> 8));
    block[11] = swap_endianness(((uint64_t)bytecode.a << 56) | ((uint64_t)bytecode.b << 24) | (bytecode.c >> 8));
    block[16] = swap_endianness(((uint64_t)bytecode.c << 56) | ((uint64_t)bytecode.d << 24) | (bytecode.e >> 8));
    block[21] = swap_endianness(((uint64_t)bytecode.e << 56) | ((uint64_t)bytecode.f << 24) | (bytecode.g >> 8));
    block[2] = swap_endianness(((uint64_t)bytecode.g << 56) | ((uint64_t)bytecode.h << 24) | (1 << 16));

    block[8] = 0x8000000000000000;

    block_permute(block);

    uint64_t b = swap_endianness(block[5]);
    uint64_t c = swap_endianness(block[10]);
    uint64_t d = swap_endianness(block[15]);

    return {(uint32_t)(b & 0xFFFFFFFF), (uint32_t)(c >> 32), (uint32_t)(c & 0xFFFFFFFF), (uint32_t)(d >> 32), (uint32_t)(d & 0xFFFFFFFF)};
}

_uint256 cpu_bind_salt(_uint256 salt, Address deployer) {
        uint64_t block[25];
        for (int i = 0; i < 25; i++) {
            block[i] = 0;
        }
    
        block[0] = cpu_swap_endianness(((uint64_t)salt.a << 32) | (uint64_t)salt.b);
        block[5] = cpu_swap_endianness(((uint64_t)salt.c << 32) | (uint64_t)salt.d);
        block[10] = cpu_swap_endianness(((uint64_t)salt.e << 32) | (uint64_t)salt.f);
        block[15] = cpu_swap_endianness(((uint64_t)salt.g << 32) | (uint64_t)salt.h);
    
        block[20] = cpu_swap_endianness(0x0000000000000000ULL);
        block[1] = cpu_swap_endianness(((uint64_t)deployer.a));
        block[6] = cpu_swap_endianness(((uint64_t)deployer.b << 32) | (uint64_t)deployer.c);
        block[11] = cpu_swap_endianness(((uint64_t)deployer.d << 32) | (uint64_t)deployer.e);
    
        block[16] = cpu_swap_endianness(0x0100000000000000ULL);
        block[8] = 0x8000000000000000ULL;
    
        cpu_block_permute(block);
    
        uint64_t a_out = cpu_swap_endianness(block[0]);
        uint64_t b_out = cpu_swap_endianness(block[5]);
        uint64_t c_out = cpu_swap_endianness(block[10]);
        uint64_t d_out = cpu_swap_endianness(block[15]);
    
        return {(uint32_t)(a_out >> 32), (uint32_t)(a_out & 0xFFFFFFFF),
                (uint32_t)(b_out >> 32), (uint32_t)(b_out & 0xFFFFFFFF),
                (uint32_t)(c_out >> 32), (uint32_t)(c_out & 0xFFFFFFFF),
                (uint32_t)(d_out >> 32), (uint32_t)(d_out & 0xFFFFFFFF)};
    }
    

Address cpu_calculate_contract_address2(Address a, Address bb, _uint256 salt, _uint256 bytecode) {
    salt = cpu_bind_salt(salt, bb);
    uint64_t block[25];
    for (int i = 0; i < 25; i++) {
        block[i] = 0;
    }

    block[0] = cpu_swap_endianness((0xFFULL << 56) | ((uint64_t)a.a << 24) | (a.b >> 8));
    block[5] = cpu_swap_endianness(((uint64_t)a.b << 56) | ((uint64_t)a.c << 24) | (a.d >> 8));
    block[10] = cpu_swap_endianness(((uint64_t)a.d << 56) | ((uint64_t)a.e << 24) | (salt.a >> 8));
    block[15] = cpu_swap_endianness(((uint64_t)salt.a << 56) | ((uint64_t)salt.b << 24) | (salt.c >> 8));
    block[20] = cpu_swap_endianness(((uint64_t)salt.c << 56) | ((uint64_t)salt.d << 24) | (salt.e >> 8));
    block[1] = cpu_swap_endianness(((uint64_t)salt.e << 56) | ((uint64_t)salt.f << 24) | (salt.g >> 8));
    block[6] = cpu_swap_endianness(((uint64_t)salt.g << 56) | ((uint64_t)salt.h << 24) | (bytecode.a >> 8));
    block[11] = cpu_swap_endianness(((uint64_t)bytecode.a << 56) | ((uint64_t)bytecode.b << 24) | (bytecode.c >> 8));
    block[16] = cpu_swap_endianness(((uint64_t)bytecode.c << 56) | ((uint64_t)bytecode.d << 24) | (bytecode.e >> 8));
    block[21] = cpu_swap_endianness(((uint64_t)bytecode.e << 56) | ((uint64_t)bytecode.f << 24) | (bytecode.g >> 8));
    block[2] = cpu_swap_endianness(((uint64_t)bytecode.g << 56) | ((uint64_t)bytecode.h << 24) | (1 << 16));

    block[8] = 0x8000000000000000;

    cpu_block_permute(block);

    uint64_t b = cpu_swap_endianness(block[5]);
    uint64_t c = cpu_swap_endianness(block[10]);
    uint64_t d = cpu_swap_endianness(block[15]);

    return {(uint32_t)(b & 0xFFFFFFFF), (uint32_t)(c >> 32), (uint32_t)(c & 0xFFFFFFFF), (uint32_t)(d >> 32), (uint32_t)(d & 0xFFFFFFFF)};
}

__global__ void __launch_bounds__(BLOCK_SIZE, 2) gpu_contract2_address_work(int score, Address a, Address b, _uint256 base_key, _uint256 bytecode) {
    uint64_t thread_id = (uint64_t)threadIdx.x + (uint64_t)blockIdx.x * (uint64_t)BLOCK_SIZE;
    uint64_t key_offset = (uint64_t)THREAD_WORK * thread_id;

    _uint256 key = base_key;
    asm(
        "add.cc.u32 %0, %0, %8;     \n\t"
        "addc.cc.u32 %1, %1, %9;    \n\t"
        "addc.cc.u32 %2, %2, 0x0;   \n\t"
        "addc.cc.u32 %3, %3, 0x0;   \n\t"
        "addc.cc.u32 %4, %4, 0x0;   \n\t"
        "addc.cc.u32 %5, %5, 0x0;   \n\t"
        "addc.cc.u32 %6, %6, 0x0;   \n\t"
        "addc.u32 %7, %7, 0x0;      \n\t"
        : "+r"(key.h), "+r"(key.g), "+r"(key.f), "+r"(key.e), "+r"(key.d), "+r"(key.c), "+r"(key.b), "+r"(key.a) : "r"((uint32_t)(key_offset & 0xFFFFFFFF)), "r"((uint32_t)(key_offset >> 32))
    );
    for (int i = 0; i < THREAD_WORK; i++) {
        handle_output2(score, calculate_contract_address2(a, b, key, bytecode), key_offset + i);
        key.h += 1;
    }
}

int global_max_score = 0;
std::mutex global_max_score_mutex;
uint32_t GRID_SIZE = 1U << 15;

struct Message {
    uint64_t time;

    int status;
    int device_index;
    cudaError_t error;

    double speed;
    int results_count;
    _uint256* results;
    int* scores;
};

std::queue<Message> message_queue;
std::mutex message_queue_mutex;


#define gpu_assert(call) { \
    cudaError_t e = call; \
    if (e != cudaSuccess) { \
        message_queue_mutex.lock(); \
        message_queue.push(Message{milliseconds(), 1, device_index, e}); \
        message_queue_mutex.unlock(); \
        if (thread_offsets_host != 0) { cudaFreeHost(thread_offsets_host); } \
        if (device_memory_host != 0) { cudaFreeHost(device_memory_host); } \
        cudaDeviceReset(); \
        return; \
    } \
}

uint64_t milliseconds() {
    return (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())).count();
}


void host_thread(int device, int device_index, int score, Address factory_address, Address eoa_address, _uint256 bytecode) {
    uint64_t GRID_WORK = ((uint64_t)BLOCK_SIZE * (uint64_t)GRID_SIZE * (uint64_t)THREAD_WORK);

    CurvePoint* thread_offsets_host = 0;

    uint64_t* device_memory_host = 0;
    uint64_t* max_score_host;
    uint64_t* output_counter_host;
    uint64_t* output_buffer_host;
    uint64_t* output_buffer2_host;

    gpu_assert(cudaSetDevice(device));
    gpu_assert(cudaHostAlloc(&device_memory_host, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t), cudaHostAllocDefault))

    output_counter_host = device_memory_host;
    max_score_host = device_memory_host + 1;
    output_buffer_host = max_score_host + 1;
    output_buffer2_host = output_buffer_host + OUTPUT_BUFFER_SIZE;

    output_counter_host[0] = 0;
    max_score_host[0] = 2;

    gpu_assert(cudaMemcpyToSymbol(device_memory, device_memory_host, 2 * sizeof(uint64_t)));
    gpu_assert(cudaDeviceSynchronize())

    _uint256 max_key = max_key = _uint256{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    _uint256 base_random_key{0, 0, 0, 0, 0, 0, 0, 0};
    int status = generate_secure_random_key(base_random_key, max_key, 256);
    _uint256 random_key_increment = cpu_mul_256_mod_p(cpu_mul_256_mod_p(uint32_to_uint256(BLOCK_SIZE), uint32_to_uint256(GRID_SIZE)), uint32_to_uint256(THREAD_WORK));
    base_random_key.h &= ~(THREAD_WORK - 1);

    if (status) {
        message_queue_mutex.lock();
        message_queue.push(Message{milliseconds(), 10 + status});
        message_queue_mutex.unlock();
        return;
    }
    _uint256 random_key = base_random_key;

    while (true) {
        uint64_t start_time = milliseconds();
        gpu_contract2_address_work<<<GRID_SIZE, BLOCK_SIZE>>>(score, factory_address, eoa_address, random_key, bytecode);

        gpu_assert(cudaDeviceSynchronize())
        gpu_assert(cudaMemcpyFromSymbol(device_memory_host, device_memory, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t)))

        uint64_t end_time = milliseconds();
        double elapsed = (end_time - start_time) / 1000.0;

        global_max_score_mutex.lock();
        if (output_counter_host[0] != 0) {
            if (max_score_host[0] > global_max_score) {
                global_max_score = max_score_host[0];
            } else {
                max_score_host[0] = global_max_score;
            }
        }
        global_max_score_mutex.unlock();

        double speed = GRID_WORK / elapsed / 1000000.0;
        if (output_counter_host[0] != 0) {
            int valid_results = 0;

            for (int i = 0; i < output_counter_host[0]; i++) {
                if (output_buffer2_host[i] < max_score_host[0]) { continue; }
                valid_results++;
            }

            if (valid_results > 0) {
                _uint256* results = new _uint256[valid_results];
                int* scores = new int[valid_results];
                valid_results = 0;

                for (int i = 0; i < output_counter_host[0]; i++) {
                    if (output_buffer2_host[i] < max_score_host[0]) { continue; }

                    uint64_t k_offset = output_buffer_host[i];
                    _uint256 k = cpu_add_256(random_key, _uint256{0, 0, 0, 0, 0, 0, (uint32_t)(k_offset >> 32), (uint32_t)(k_offset & 0xFFFFFFFF)});
        
                    int idx = valid_results++;
                    results[idx] = k;
                    scores[idx] = output_buffer2_host[i];
                }

                message_queue_mutex.lock();
                message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, valid_results, results, scores});
                message_queue_mutex.unlock();
            } else {
                message_queue_mutex.lock();
                message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                message_queue_mutex.unlock();
            }
        } else {
            message_queue_mutex.lock();
            message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
            message_queue_mutex.unlock();
        }

        random_key = cpu_add_256(random_key, random_key_increment);

        output_counter_host[0] = 0;
        gpu_assert(cudaMemcpyToSymbol(device_memory, device_memory_host, sizeof(uint64_t)));
    }
}


void print_speeds(int num_devices, int* device_ids, double* speeds) {
    double total = 0.0;
    for (int i = 0; i < num_devices; i++) {
        total += speeds[i];
    }

    printf("Total: %.2fM/s", total);
    for (int i = 0; i < num_devices; i++) {
        printf("  DEVICE %d: %.2fM/s", device_ids[i], speeds[i]);
    }
}


int main(int argc, char *argv[]) {
    int score = -1;
    char* input_file = 0;
    char* factory = 0;
    char* eoa = 0;
    int num_devices = 0;
    int device_ids[10];

    for (int i = 1; i < argc;) {
        if (strcmp(argv[i], "--device") == 0) {
            device_ids[num_devices++] = atoi(argv[i + 1]);
            i += 2;
        } else if (strcmp(argv[i], "--bytecode") == 0) {
            input_file = argv[i + 1];
            i += 2;
        } else if  (strcmp(argv[i], "--factory") == 0) {
            factory = argv[i + 1];
            i += 2;
        } else if  (strcmp(argv[i], "--eoa") == 0) {
            eoa = argv[i + 1];
            i += 2;
        } else if  (strcmp(argv[i], "--score") == 0) {
            score = atoi(argv[i + 1]);
            i += 2;
        } else if  (strcmp(argv[i], "--work-scale") == 0) {
            GRID_SIZE = 1U << atoi(argv[i + 1]);
            i += 2;
        } else {
            i++;
        }
    }

    if (num_devices == 0) {
        printf("No devices were specified\n");
        return 1;
    }

    if (!score) {
        printf("You must specify a target score\n");
        return 1;
    }

    if (!input_file) {
        printf("You must specify contract bytecode\n");
        return 1;
    }

    if (!factory) {
        printf("You must specify an factory address\n");
        return 1;
    }

    if (!eoa) {
        printf("You must specify an EOA address\n");
        return 1;
    }

    for (int i = 0; i < num_devices; i++) {
        cudaError_t e = cudaSetDevice(device_ids[i]);
        if (e != cudaSuccess) {
            printf("Could not detect device %d\n", device_ids[i]);
            return 1;
        }
    }

    _uint256 bytecode_hash;
    std::ifstream infile(input_file, std::ios::binary);
    if (!infile.is_open()) {
        printf("Failed to open the bytecode file.\n");
        return 1;
    }
    
    int file_size = 0;
    {
        infile.seekg(0, std::ios::end);
        std::streampos file_size_ = infile.tellg();
        infile.seekg(0, std::ios::beg);
        file_size = file_size_ - infile.tellg();
    }

    if (file_size & 1) {
        printf("Invalid bytecode in file. - %d\n", file_size);
        return 1;
    }

    uint8_t* bytecode = new uint8_t[24576];
    if (bytecode == 0) {
        printf("Error while allocating memory. Perhaps you are out of memory?");
        return 1;
    }

    char byte[2];
    bool prefix = false;
    for (int i = 0; i < (file_size >> 1); i++) {
        infile.read((char*)&byte, 2);
        if (i == 0) {
            prefix = byte[0] == '0' && byte[1] == 'x';
            if ((file_size >> 1) > (prefix ? 24577 : 24576)) {
                printf("Invalid bytecode in file.\n");
                delete[] bytecode;
                return 1;
            }
            if (prefix) { continue; }
        }
        bytecode[i - prefix] = (uint8_t)strtol(byte, 0, 16);
    }    
    bytecode_hash = cpu_full_keccak(bytecode, (file_size >> 1) - prefix);
    delete[] bytecode;

    Address factory_address;
    if (strlen(factory) == 42) factory += 2;
    char substr[9];
    #define round(i, offset) \
    strncpy(substr, factory + offset * 8, 8); \
    factory_address.i = strtoull(substr, 0, 16);
    round(a, 0)
    round(b, 1)
    round(c, 2)
    round(d, 3)
    round(e, 4)
    #undef round

    Address eoa_address;
    if (strlen(eoa) == 42) eoa += 2;
    #define round(i, offset) \
    strncpy(substr, eoa + offset * 8, 8); \
    eoa_address.i = strtoull(substr, 0, 16);
    round(a, 0)
    round(b, 1)
    round(c, 2)
    round(d, 3)
    round(e, 4)
    #undef round


    std::vector<std::thread> threads;
    uint64_t global_start_time = milliseconds();
    for (int i = 0; i < num_devices; i++) {
        std::thread th(host_thread, device_ids[i], i, score, factory_address, eoa_address, bytecode_hash);
        threads.push_back(move(th));
    }

    double speeds[100];
    while(true) {
        message_queue_mutex.lock();
        if (message_queue.size() == 0) {
            message_queue_mutex.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        } else {
            while (!message_queue.empty()) {
                Message m = message_queue.front();
                message_queue.pop();

                int device_index = m.device_index;

                if (m.status == 0) {
                    speeds[device_index] = m.speed;

                    printf("\r");
                    if (m.results_count != 0) {
                        Address* addresses = new Address[m.results_count];
                        for (int i = 0; i < m.results_count; i++)
                            addresses[i] = cpu_calculate_contract_address2(factory_address, eoa_address, m.results[i], bytecode_hash);

                        for (int i = 0; i < m.results_count; i++) {
                            _uint256 k = m.results[i];
                            int score = m.scores[i];
                            Address a = addresses[i];
                            uint64_t time = (m.time - global_start_time) / 1000;
                            printf("Elapsed: %06u Score: %02u Salt: 0x%08x%08x%08x%08x%08x%08x%08x%08x Address: 0x%08x%08x%08x%08x%08x\n", (uint32_t)time, score, k.a, k.b, k.c, k.d, k.e, k.f, k.g, k.h, a.a, a.b, a.c, a.d, a.e);
                        }

                        delete[] addresses;
                        delete[] m.results;
                        delete[] m.scores;
                    }
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 1) {
                    printf("\rCuda error %d on device %d. Device will halt work.\n", m.error, device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 11) {
                    printf("\rError from BCryptGenRandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 12) {
                    printf("\rError while reading from /dev/urandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 13) {
                    printf("\rError while opening /dev/urandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 100) {
                    printf("\rError while allocating memory. Perhaps you are out of memory? Device %d will halt work.", device_ids[device_index]);
                }
            }
            message_queue_mutex.unlock();
        }
    }
}