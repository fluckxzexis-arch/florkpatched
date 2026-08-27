/* Fluck AuthKit bypass v3 — the offline-patched binary companion.
   The binary's 8 AuthKit entries are patched (patch_binary.py) with 12-byte
   stubs: adrp x16, slot; ldr x16, [x16]; br x16 — the slots live in the
   extended __bss (FLUCK_BSS_SLOT_BASE) and are filled here at load time.

   slot[0] DecryptEnvelope       -> FFDecryptFix  (nil -> the real manifest)
   slot[1] HasValidLicense       -> FFForceYes
   slot[2] PrepareProtectedSync  -> FFForceOne
   slot[3] PrepareProtectedAsync -> FFForceOne
   slot[4] VerifySignature       -> FFForceYes
   slot[5] OffsetsCurrentGameVer -> FFGameVersion
   slot[6] OffsetsCurrentProfile -> FFProfile
   slot[7] OffsetsCurrentRevision-> FFRevisionOne
*/
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#include <dlfcn.h>
#include <string.h>

#include "reloc.h"

/* ── the real manifest (flork offsets, captured from the live server) ── */
static NSString *const kManifestJSON =
    @"{\"schema\":\"flork.offsets.v1\",\"project\":\"freefire\",\"product\":\"freefire\","
    @"\"profile\":\"freefire\",\"game_version\":\"legacy-snapshot-2026-07-21\","
    @"\"offset_revision\":5,\"app_version\":\"1.0\",\"offset_version\":2,"
    @"\"expires_at\":1893456000,\"offsets\":{"
    @"\"module\":{\"game_facade_type_info\":\"0xC012848\"},"
    @"\"game_facade\":{\"match\":\"0x90\",\"camera_controller_manager\":\"0xD8\"},"
    @"\"camera_controller_manager\":{\"main_camera\":\"0x20\"},"
    @"\"match\":{\"local_player\":\"0xD8\",\"player_collection\":\"0x148\"},"
    @"\"player\":{\"nickname\":\"0x428\",\"main_camera_transform\":\"0x380\","
    @"\"wait_for_force_sync\":\"0x798\",\"bones\":{\"head\":\"0x638\",\"hip\":\"0x640\","
    @"\"left_hand\":\"0x690\",\"right_hand\":\"0x630\",\"left_ankle\":\"0x678\","
    @"\"right_ankle\":\"0x670\",\"left_toe\":\"0x688\",\"right_toe\":\"0x680\"},"
    @"\"visibility\":\"0xA50\",\"player_id\":\"0x3A0\",\"pri_data_pool\":\"0x70\","
    @"\"attributes\":\"0x700\",\"inventory_manager\":\"0x6D8\",\"physx_data\":\"0x1B80\","
    @"\"head_collider\":\"0x6D0\",\"aim_assist_target\":\"0x80\",\"aim_rotation\":\"0x5AC\","
    @"\"hit_object_info\":\"0xDC8\"},"
    @"\"hit_object_info\":{\"ray_direction\":\"0x40\",\"start_position\":\"0x4C\"},"
    @"\"attributes\":{\"fast_reload\":\"0xD9\",\"fast_medikit\":\"0xCC\","
    @"\"fire_interval_scale\":\"0x208\",\"falling_speed_scale\":\"0x26C\","
    @"\"run_speed_scale\":\"0x270\"},"
    @"\"inventory_manager\":{\"current_item\":\"0xA0\"},"
    @"\"weapon_item\":{\"recoil_context\":\"0x80\",\"state_machine\":\"0x90\","
    @"\"is_sighting\":\"0x7C0\"},"
    @"\"recoil_context\":{\"value\":\"0x18\"},"
    @"\"weapon_state_machine\":{\"current_state\":\"0x18\"},"
    @"\"weapon_state\":{\"value\":\"0x10\"},"
    @"\"physx_data\":{\"state\":\"0x20\"},"
    @"\"physx_state\":{\"pose\":\"0x10\"},"
    @"\"getMatchGame\":{\"gameFacadeTypeInfo\":\"0xC012848\"}}}";

static NSData *gManifestData = nil;

NSData *FFManifestData(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gManifestData = [kManifestJSON dataUsingEncoding:NSUTF8StringEncoding];
    });
    return gManifestData;
}

/* ── runtime base ── */
static void *FFMainBase(void) {
    if (_dyld_image_count() == 0) return NULL;
    return (void *)(0x100000000ULL + _dyld_get_image_vmaddr_slide(0));
}

/* ── exported trampolines ── */

__attribute__((visibility("default"))) BOOL FFForceYes(void) { return YES; }
__attribute__((visibility("default"))) uintptr_t FFForceOne(void) { return 1; }
__attribute__((visibility("default"))) NSString *FFGameVersion(void) { return @"1.0"; }
__attribute__((visibility("default"))) NSString *FFProfile(void) { return @"freefire"; }
__attribute__((visibility("default"))) NSNumber *FFRevisionOne(void) {
    static NSNumber *rev = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ rev = @1; });
    return rev;
}

/* The decrypt fix: re-execute the overwritten prologue (reloc.h) then continue
   into the original body; if the result is nil, return our manifest. */

static void *gDecryptTail = NULL;

__attribute__((naked, noinline)) static void *FFDecryptRealEntry(void *a0, void *a1, void *a2, void *a3) {
    __asm__ volatile(
        ".inst 0xA9BA6FFC\n"      /* stp x28, x27, [sp, #-0x60]!  (FLUCK_RELOC_DECRYPTENVELOPE) */
        ".inst 0xA90167FA\n"      /* stp x26, x25, [sp, #0x10] */
        ".inst 0xA9025FF8\n"      /* stp x24, x23, [sp, #0x20] */
        "adrp x16, _gDecryptTail@PAGE\n"
        "ldr  x16, [x16, _gDecryptTail@PAGEOFF]\n"
        "br   x16\n"
    );
}

__attribute__((visibility("default"))) void *FFDecryptFix(void *dict, void *key, void *s1, void *s2) {
    void *r = FFDecryptRealEntry(dict, key, s1, s2);
    if (r == NULL) r = (void *)CFBridgingRetain(FFManifestData());
    return r;
}

/* ── swizzles ── */

static NSString *FFRedirectedURLString(NSString *orig) {
    if ([orig rangeOfString:@"fl0rk.io.vn"].location != NSNotFound) {
        return [orig stringByReplacingOccurrencesOfString:@"fl0rk.io.vn" withString:@"fluckv2.org"];
    }
    return orig;
}

static NSURL *FFURLWithString(id self, SEL _cmd, NSString *str) {
    NSString *r = FFRedirectedURLString(str);
    return ((NSURL *(*)(id, SEL, NSString *))objc_msgSend)(self, _cmd, r);
}

static NSString *FFSystemVersion(id self, SEL _cmd) { return @"18.5"; }
static NSString *FFModel(id self, SEL _cmd) { return @"iPhone"; }
static NSString *FFOSVersionString(id self, SEL _cmd) { return @"Version 18.5 (Build 22F76)"; }

static void FFInstallSwizzles(void) {
    Method m;

    m = class_getClassMethod(objc_getClass("NSURL"), @selector(URLWithString:));
    if (m) method_setImplementation(m, (IMP)FFURLWithString);

    m = class_getInstanceMethod(objc_getClass("UIDevice"), @selector(systemVersion));
    if (m) method_setImplementation(m, (IMP)FFSystemVersion);

    m = class_getInstanceMethod(objc_getClass("UIDevice"), @selector(model));
    if (m) method_setImplementation(m, (IMP)FFModel);

    m = class_getInstanceMethod(objc_getClass("NSProcessInfo"), @selector(operatingSystemVersionString));
    if (m) method_setImplementation(m, (IMP)FFOSVersionString);

    NSLog(@"[FluckBypass] swizzles installed");
}

/* ── slot fill ── */

static void FFFillSlots(void) {
    void *base = FFMainBase();
    if (!base) return;
    uintptr_t slotsAddr = (uintptr_t)base + (FLUCK_BSS_SLOT_BASE - 0x100000000ULL);
    void **slots = (void **)slotsAddr;
    slots[0] = (void *)FFDecryptFix;
    slots[1] = (void *)FFForceYes;
    slots[2] = (void *)FFForceOne;
    slots[3] = (void *)FFForceOne;
    slots[4] = (void *)FFForceYes;
    slots[5] = (void *)FFGameVersion;
    slots[6] = (void *)FFProfile;
    slots[7] = (void *)FFRevisionOne;
    gDecryptTail = (void *)((uintptr_t)base + 0x350b4 + 12 - 0x100000000ULL);
    NSLog(@"[FluckBypass] slots filled @0x%llx, decrypt tail @%p", (unsigned long long)slotsAddr, gDecryptTail);
}

/* ── startup ── */

__attribute__((constructor)) static void FFBypassInit(void) {
    FFInstallSwizzles();
    FFManifestData();
    FFFillSlots();
    NSLog(@"[FluckBypass] v3 loaded");
}
