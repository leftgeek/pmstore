/* Emulate latency */
#undef PCM_EMULATE_LATENCY
#define PCM_EMULATE_LATENCY 0x1
#undef PCM_EMULATE_LATENCY_READ
#define PCM_EMULATE_LATENCY_READ

/* CPU frequency */
#define PCM_CPUFREQ 2100LLU /* GHz */

/* PCM write latency*/
#define PCM_LATENCY_WRITE 200 /* ns */
#define PCM_LATENCY_READ 50 /* ns */

/* PCM write bandwidth */
//#define PCM_BANDWIDTH_MB 4000
//#define PCM_BANDWIDTH_MB 600
//#define PCM_BANDWIDTH_MB 300
//2000:150ns(PCM speed in theory),300:1000ns(practical speed of PCM),150:2000ns

/* DRAM system peak bandwidth */
//#define DRAM_BANDWIDTH_MB 24000

#define NS2CYCLE(__ns) ((__ns) * PCM_CPUFREQ / 1000)
#define CYCLE2NS(__cycles) ((__cycles) * 1000 / PCM_CPUFREQ)

#define gethrtime       asm_rdtsc

/* Public types */
typedef uint64_t pcm_hrtime_t;

#if defined(__i386__)

static inline unsigned long long asm_rdtsc(void)
{
	unsigned long long int x;
	__asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
	return x;
}

static inline unsigned long long asm_rdtscp(void)
{
		unsigned hi, lo;
	__asm__ __volatile__ ("rdtscp" : "=a"(lo), "=d"(hi)::"ecx");
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );

}
#elif defined(__x86_64__)

static inline unsigned long long asm_rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

static inline unsigned long long asm_rdtscp(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtscp" : "=a"(lo), "=d"(hi)::"rcx");
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}
#else
#error "What architecture is this???"
#endif

static inline
void
emulate_latency_ns(int ns)
{
	pcm_hrtime_t cycles;
	pcm_hrtime_t start;
	pcm_hrtime_t stop;
	
  //printk(KERN_ERR "@emulate_latency_ns: %d\n", ns);
	start = asm_rdtsc();
	cycles = NS2CYCLE(((ns + 63) / 64) * PCM_LATENCY_WRITE);

	do { 
		/* RDTSC doesn't necessarily wait for previous instructions to complete 
		 * so a serializing instruction is usually used to ensure previous 
		 * instructions have completed. However, in our case this is a desirable
		 * property since we want to overlap the latency we emulate with the
		 * actual latency of the emulated instruction. 
		 */
		stop = asm_rdtsc();
	} while (stop - start < cycles);
}
//模拟延迟时是以cacheline为单位模拟，还是集中模拟
#undef OBJVFS_LATENCY_GRANULARITY_CACHELINE
//#define OBJVFS_LATENCY_GRANULARITY_CACHELINE
static inline
void
emulate_latency_ns_read(int ns)
{
	pcm_hrtime_t cycles;
	pcm_hrtime_t start;
	pcm_hrtime_t stop;
	
  //printk(KERN_ERR "@emulate_latency_ns_read: %d\n", ns);
	start = asm_rdtsc();
	cycles = NS2CYCLE(((ns + 63) / 64) * PCM_LATENCY_READ);

	do { 
		/* RDTSC doesn't necessarily wait for previous instructions to complete 
		 * so a serializing instruction is usually used to ensure previous 
		 * instructions have completed. However, in our case this is a desirable
		 * property since we want to overlap the latency we emulate with the
		 * actual latency of the emulated instruction. 
		 */
		stop = asm_rdtsc();
	} while (stop - start < cycles);
}
