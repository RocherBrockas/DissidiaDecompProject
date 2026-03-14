#include <pspkernel.h>
#include <pspthreadman.h>

// Defined in data segment - file paths used elsewhere in the binary
// (referenced by FUN_0893354c, not needed here but documented for context)
// "general_archive/main/main.bin"
// "general_archive/main/JP/main_lan_*.bin"
// "general_archive/main/main_prolog_*.bin"

// Forward declaration - entry point of the main game thread
static int ffst_thread(SceSize args, void *argp);

int module_start(SceSize args, void *argp)
{
    SceUID thread_id;

    sceKernelSetCompiledSdkVersion603_605(0x6030010);
    sceKernelSetCompilerVersion(0x030306);

    thread_id = sceKernelCreateThread(
        "ffst_thread",  // thread name
        ffst_thread,    // entry point (LAB_08804160)
        0x30,           // priority (DAT_089d85a8)
        0x40 << 10,     // stack size = 64 KB (DAT_089d85a4 << 10)
        0x80000000,     // PSP_THREAD_ATTR_VSH - runs in kernel/VSH context
        NULL            // SceKernelThreadOptParam* - no options
    );

    if (thread_id >= 0) {
        sceKernelStartThread(thread_id, args, argp);
    }

    return (thread_id < 0) ? -1 : 0;
}