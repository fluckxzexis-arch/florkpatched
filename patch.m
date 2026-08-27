// FluckAuth patch.dylib — replaces Fl0rkFF KeyAuth with Fluck license system.
// Injected into Fl0rkFF (Fluck) via LC_LOAD_DYLIB.
//
// Protocol mirrors the Fluck app (FluckAuthCore):
//   1. GET  https://fluckv2.org/server.php?action=check_package&app_id=%@&version=%@
//      -> { success, encrypted_data (AES-256-CBC), timestamp, signature }
//      signature = sha256(encrypted_data + timestamp + AES_KEY)
//   2. POST https://fluckv2.org/server.php  body:
//      { data: xorHex(jsonPayload, rollingKey), timestamp, udid, format: "full_encrypted" }
//      payload = { password: sha256(udid+ts+SECRET), udid, timestamp, license_key,
//                  app_id, package_id }
//      rollingKey = hex(sha256("Fluck2020@Zexis" + ts + udid[0..8])[0..16])
//   3. response { data, timestamp, format } -> xor decrypt -> { var: "momo" = OK,
//      reason }
//
// On success: save key + fire the app's unlockHandler block (gate removed).

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <Security/Security.h>
#import <sys/utsname.h>

void FFInstallAuthKitBypass(void);

/* ─── config (match server-side packages) ─── */
static NSString *const kServerURL      = @"https://fluckv2.org/server.php";
static NSString *const kAppID          = @"com.patched.fluck";
static NSString *const kAppVersion     = @"1.0.0";
static NSString *const kBaseEncKey     = @"Fluck2020@Zexis";
static NSString *const kSecretPassword = @"@IamGayBecauseYouAreSexy";
static NSString *const kAesKey         = @"ZexisFluckPackageSecretKey2025!!";
static NSString *const kAesIV          = @"FluckIV123456789";

static NSString *const kSavedKeyDefaults = @"fluck.license.key";

/* ─── helpers ─── */

static NSString *FFSha256Hex(NSString *input) {
    if (!input) return @"";
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *out = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [out appendFormat:@"%02x", digest[i]];
    return out;
}

static NSString *FFSha256HexData(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *out = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [out appendFormat:@"%02x", digest[i]];
    return out;
}

static NSString *FFUdid(void) {
    static NSString *udid = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct utsname info;
        NSString *combined = @"unknown";
        if (uname(&info) == 0) {
            NSString *model = [NSString stringWithCString:info.machine encoding:NSUTF8StringEncoding] ?: @"unknown";
            NSString *version = [UIDevice currentDevice].systemVersion ?: @"unknown";
            NSString *name = [UIDevice currentDevice].name ?: @"unknown";
            combined = [NSString stringWithFormat:@"%@-%@-%@", model, version, name];
        }
        udid = FFSha256Hex(combined) ?: @"";
    });
    return udid;
}

static NSString *FFRollingKey(NSInteger ts, NSString *udid) {
    NSString *udidPart = [udid substringToIndex:MIN(8, udid.length)];
    NSString *combined = [NSString stringWithFormat:@"%@%ld%@", kBaseEncKey, (long)ts, udidPart];
    NSData *hash = [combined dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(hash.bytes, (CC_LONG)hash.length, digest);
    NSMutableString *out = [NSMutableString stringWithCapacity:32];
    for (int i = 0; i < 16; i++)
        [out appendFormat:@"%02x", digest[i]];
    return out;
}

static NSString *FFXorEncryptHex(NSString *input, NSString *key) {
    if (!input || !key || input.length == 0 || key.length == 0) return nil;
    NSData *inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    const unsigned char *ib = inputData.bytes;
    const unsigned char *kb = keyData.bytes;
    NSUInteger klen = keyData.length;
    NSMutableString *hex = [NSMutableString stringWithCapacity:inputData.length * 2];
    for (NSUInteger i = 0; i < inputData.length; i++) {
        unsigned char c = ib[i] ^ kb[i % klen];
        [hex appendFormat:@"%02x", c];
    }
    return hex;
}

static NSString *FFXorDecryptHex(NSString *hexInput, NSString *key) {
    if (!hexInput || !key || hexInput.length == 0 || key.length == 0) return nil;
    NSMutableData *data = [NSMutableData dataWithCapacity:hexInput.length / 2];
    for (NSUInteger i = 0; i + 1 < hexInput.length; i += 2) {
        NSString *hexByte = [hexInput substringWithRange:NSMakeRange(i, 2)];
        NSScanner *scanner = [NSScanner scannerWithString:hexByte];
        unsigned int v;
        if (![scanner scanHexInt:&v]) return nil;
        uint8_t byte = (uint8_t)v;
        [data appendBytes:&byte length:1];
    }
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    const unsigned char *kb = keyData.bytes;
    NSUInteger klen = keyData.length;
    NSMutableData *result = [NSMutableData dataWithLength:data.length];
    unsigned char *rb = result.mutableBytes;
    const unsigned char *db = data.bytes;
    for (NSUInteger i = 0; i < data.length; i++)
        rb[i] = db[i] ^ kb[i % klen];
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

static NSData *FFAesDecrypt(NSString *b64Input) {
    if (!b64Input) return nil;
    NSData *enc = [[NSData alloc] initWithBase64EncodedString:b64Input options:0];
    if (!enc) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:enc.length + kCCBlockSizeAES128];
    size_t moved = 0;
    /* server: key = sha256(AES_KEY_STR)[0..32], iv = sha256(AES_IV_STR)[0..16] */
    NSData *keyFull = [kAesKey dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivFull = [kAesIV dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char kd[CC_SHA256_DIGEST_LENGTH], id_[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(keyFull.bytes, (CC_LONG)keyFull.length, kd);
    CC_SHA256(ivFull.bytes, (CC_LONG)ivFull.length, id_);
    NSData *keyData = [NSData dataWithBytes:kd length:32];
    NSData *ivData = [NSData dataWithBytes:id_ length:16];
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                 keyData.bytes, kCCKeySizeAES256, ivData.bytes,
                                 enc.bytes, enc.length, out.mutableBytes, out.length, &moved);
    if (st != kCCSuccess) return nil;
    return [out subdataWithRange:NSMakeRange(0, moved)];
}

/* ─── server calls ─── */

static NSString *gPackageId = nil;

static void FFCheckPackage(void (^done)(BOOL ok, NSString *err)) {
    NSString *urlString = [NSString stringWithFormat:@"%@?action=check_package&app_id=%@&version=%@",
                           kServerURL, kAppID, kAppVersion];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    req.HTTPMethod = @"GET";
    req.timeoutInterval = 10;
    req.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        BOOL ok = NO;
        NSString *errorText = @"package_check_failed";
        if (!err && data) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json && [json[@"success"] boolValue]) {
                NSString *encData = json[@"encrypted_data"];
                NSNumber *ts = json[@"timestamp"];
                NSString *sig = json[@"signature"];
                if (encData && ts && sig) {
                    NSString *expect = FFSha256Hex([NSString stringWithFormat:@"%@%ld%@",
                                                    encData, (long)[ts longValue], kAesKey]);
                    if ([sig isEqualToString:expect]) {
                        NSData *dec = FFAesDecrypt(encData);
                        NSDictionary *pkg = dec ? [NSJSONSerialization JSONObjectWithData:dec options:0 error:nil] : nil;
                        if (pkg && [pkg[@"app_id"] isEqualToString:kAppID] &&
                            [pkg[@"version"] isEqualToString:kAppVersion] &&
                            [pkg[@"status"] isEqualToString:@"active"]) {
                            gPackageId = pkg[@"package_id"];
                            ok = YES;
                            errorText = nil;
                        } else {
                            errorText = pkg ? @"package_inactive" : @"decryption_failed";
                        }
                    } else {
                        errorText = @"signature_mismatch";
                    }
                } else {
                    errorText = @"invalid_response";
                }
            } else {
                errorText = json[@"error"] ?: @"package_check_failed";
            }
        } else {
            errorText = @"network_error";
        }
        if (done) done(ok, errorText);
    }] resume];
}

static void FFVerifyKey(NSString *key, void (^done)(BOOL ok, NSString *reason)) {
    NSInteger ts = (NSInteger)[[NSDate date] timeIntervalSince1970];
    NSString *udid = FFUdid();
    NSString *challengeInput = [NSString stringWithFormat:@"%@%ld%@", udid, (long)ts, kSecretPassword];
    NSString *challenge = FFSha256Hex(challengeInput);

    NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithDictionary:@{
        @"password": challenge,
        @"udid": udid,
        @"timestamp": @(ts),
        @"license_key": key,
        @"app_id": kAppID
    }];
    if (gPackageId.length)
        payload[@"package_id"] = gPackageId;

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (!jsonData) { if (done) done(NO, @"json_error"); return; }
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *rollingKey = FFRollingKey(ts, udid);
    NSString *encryptedPayload = FFXorEncryptHex(jsonString, rollingKey);
    if (!encryptedPayload) { if (done) done(NO, @"encryption_failed"); return; }

    NSDictionary *requestBody = @{
        @"data": encryptedPayload,
        @"timestamp": @(ts),
        @"udid": udid,
        @"format": @"full_encrypted"
    };
    NSData *requestData = [NSJSONSerialization dataWithJSONObject:requestBody options:0 error:nil];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kServerURL]];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 12;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = requestData;

    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        BOOL ok = NO;
        NSString *reason = @"network_error";
        if (!err && data) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json && json[@"data"] && json[@"timestamp"] && json[@"format"]) {
                NSString *enc = json[@"data"];
                NSInteger serverTs = [json[@"timestamp"] integerValue];
                NSString *rk = FFRollingKey(serverTs, FFUdid());
                NSString *dec = FFXorDecryptHex(enc, rk);
                NSDictionary *dj = dec ? [NSJSONSerialization JSONObjectWithData:[dec dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil] : nil;
                if (dj) {
                    reason = dj[@"reason"] ?: @"unknown";
                    if ([dj[@"var"] isEqualToString:@"momo"]) {
                        ok = YES;
                    }
                } else {
                    reason = @"decryption_failed";
                }
            } else {
                reason = json[@"reason"] ?: @"invalid_response";
            }
        }
        if (done) done(ok, reason);
    }] resume];
}

/* ─── keychain helper (app's own keychain service) ─── */

static NSData *FFKeychainSave(NSString *account, NSString *value) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"com.fl0rk.ff.darksword.auth",
        (__bridge id)kSecAttrAccount: account,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *add = [query mutableCopy];
    add[(__bridge id)kSecValueData] = data;
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    return st == errSecSuccess ? data : nil;
}

/* ─── app integration (swizzle AuthGateViewController) ─── */

static void FFCallUnlock(id self) {
    id blk = [self valueForKey:@"unlockHandler"];
    if (blk) {
        void (^handler)(void) = (void (^)(void))blk;
        if (handler) handler();
    }
}

static void FFSetStatus(id self, NSString *text) {
    id label = [self valueForKey:@"statusLabel"];
    if (label && [label respondsToSelector:@selector(setText:)])
        [label setText:text];
}

static void FFShowMessage(id self, NSString *message) {
    SEL sel = sel_registerName("showInputWithMessage:");
    if ([self respondsToSelector:sel]) {
        ((void (*)(id, SEL, id))objc_msgSend)(self, sel, message);
    }
}

static void FFRunAuth(id self) {
    /* key from text field, fallback to saved key */
    NSString *key = nil;
    id kf = [self valueForKey:@"keyField"];
    if (kf && [kf respondsToSelector:@selector(text)])
        key = [kf text];
    if (!key.length)
        key = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKeyDefaults];

    if (!key.length) {
        FFShowMessage(self, @"Enter your license key.");
        return;
    }

    FFSetStatus(self, @"Verifying…");

    void (^verify)(void) = ^{
        FFVerifyKey(key, ^(BOOL ok, NSString *reason) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (ok) {
                    [[NSUserDefaults standardUserDefaults] setObject:key forKey:kSavedKeyDefaults];
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    /* also feed the ORIGINAL AuthKit user-key slot so the
                       protected ESP access flow enrolls with a real key */
                    [FFKeychainSave(@"UserKey.Fl0rkFF", @"FreeFire-DS-756083") length];
                    FFSetStatus(self, @"Activated.");
                    FFCallUnlock(self);
                } else {
                    FFShowMessage(self, reason ?: @"invalid_key");
                }
            });
        });
    };

    if (gPackageId.length) {
        verify();
    } else {
        FFCheckPackage(^(BOOL ok, NSString *err) {
            if (ok) {
                verify();
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    FFShowMessage(self, err ?: @"package_check_failed");
                });
            }
        });
    }
}

static void FFInstallSwizzle(void) {
    Class cls = objc_getClass("AuthGateViewController");
    if (!cls) return;

    /* beginInitialValidation: saved key -> verify + unlock; else show gate */
    {
        SEL sel = sel_registerName("beginInitialValidation");
        Method m = class_getInstanceMethod(cls, sel);
        if (m) {
            IMP imp = imp_implementationWithBlock(^(id _self) {
                NSString *saved = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKeyDefaults];
                if (saved.length) {
                    FFRunAuth(_self);
                }
            });
            method_setImplementation(m, imp);
        }
    }

    /* validateSavedKey + loginButtonPressed: -> our auth flow */
    const char *sels[] = { "validateSavedKey", "loginButtonPressed:" };
    for (unsigned i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
        SEL sel = sel_registerName(sels[i]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) continue;
        IMP imp = imp_implementationWithBlock(^(id _self) {
            FFRunAuth(_self);
        });
        method_setImplementation(m, imp);
    }
}

/* ESP gate bypass: fake iOS version + block unsupported dialog */

static void FFInstallEspBypass(void) {
    Class uid = objc_getClass("UIDevice");
    if (uid) {
        Method m = class_getInstanceMethod(uid, sel_registerName("systemVersion"));
        if (m) {
            IMP imp = imp_implementationWithBlock(^NSString *(id _self) {
                return @"18.5";
            });
            method_setImplementation(m, imp);
        }
    }
    Class esp = objc_getClass("ESPInstallerViewController");
    if (esp) {
        Method m = class_getInstanceMethod(esp, sel_registerName("presentUnsupportedAlert"));
        if (m) {
            IMP imp = imp_implementationWithBlock(^(id _self) {
                /* no-op — dialog blocked */
            });
            method_setImplementation(m, imp);
        }
        /* ensure AuthKit gates are kernel-patched before activation runs */
        const char *gates[] = { "setESPEnabledAndRun:", "toggleESP" };
        for (unsigned i = 0; i < sizeof(gates) / sizeof(gates[0]); i++) {
            Method g = class_getInstanceMethod(esp, sel_registerName(gates[i]));
            if (!g) continue;
            IMP origImp = method_getImplementation(g);
            const char *gateName = gates[i];
            SEL gateSel = sel_registerName(gateName);
            IMP imp = imp_implementationWithBlock(^(id _self, id arg) {
                FFInstallAuthKitBypass();
                return ((id (*)(id, SEL, id))origImp)(_self, gateSel, arg);
            });
            method_setImplementation(g, imp);
        }
    }
}

/* ─── AuthKit full bypass + embedded offsets table ───
   The "Protected ESP access" flow (AuthKitPrepareProtectedAccessSync) fails
   locally because the license token/enrollment is missing (old auth server
   gone). We replace the whole chain:
     - HasValidLicense -> 1
     - VerifySignature  -> 1
     - PrepareProtectedAccessSync/Async -> 1
     - FreeFireOffsetRead(name, out) -> look up our embedded table
   Offsets are the OB54 values from the Fluck project (offset.h) — game
   offsets didn't change. */

static const struct { const char *name; uint64_t value; } kFluckOffsets[] = {
    {"moduleGameFacadeTypeInfo",          0xC012848},
    {"gameFacadeMatch",                   0x90},
    {"gameFacadeCameraControllerManager", 0xD8},
    {"cameraControllerManagerMainCamera", 0x20},
    {"matchLocalPlayer",                  0xD8},
    {"matchPlayerCollection",             0x148},
    {"playerNickname",                    0x438},
    {"playerMainCameraTransform",         0x380},
    {"playerWaitForForceSync",            0x0},
    {"playerBoneHead",                    0x638},
    {"playerBoneHip",                     0x640},
    {"playerBoneRightToe",                0x688},
    {"playerVisibility",                  0xA50},
    {"playerId",                          0x3A0},
    {"playerPriDataPool",                 0x70},
    {"playerAttributes",                  0x700},
    {"playerInventoryManager",            0x690},
    {"playerPhysXData",                   0x1B80},
    {"playerHeadCollider",                0x0},
    {"playerAimAssistTarget",             0x0},
    {"playerAimRotation",                 0x5AC},
    {"playerHitObjectInfo",               0x0},
    {"hitObjectInfoRayDirection",         0x0},
    {"hitObjectInfoStartPosition",        0x0},
    {"attributesFastReload",              0xD9},
    {"attributesFastMedikit",             0x0},
    {"attributesFireIntervalScale",       0x208},
    {"attributesFallingSpeedScale",       0x0},
    {"attributesRunSpeedScale",           0x0},
    {"inventoryManagerCurrentItem",       0x690},
    {"weaponItemRecoilContext",           0x0},
    {"weaponItemStateMachine",            0x0},
    {"weaponItemIsSighting",              0x0},
    {"recoilContextValue",                0x0},
    {"weaponStateMachineCurrentState",    0x0},
    {"weaponStateValue",                  0x0},
    {"physXDataState",                    0x10},
    {"physXStatePose",                    0x20},
};

static uint64_t FFLookupOffset(const char *name) {
    for (unsigned i = 0; i < sizeof(kFluckOffsets) / sizeof(kFluckOffsets[0]); i++) {
        if (strcmp(kFluckOffsets[i].name, name) == 0)
            return kFluckOffsets[i].value;
    }
    return 0;
}

__attribute__((constructor))
static void FluckPatchInit(void) {
    FFInstallSwizzle();
    FFInstallEspBypass();
    extern void FFInstallAuthKitBypass(void);
    /* entry patching after launch (mprotect fails during dyld constructor) */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ FFInstallAuthKitBypass(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ FFInstallAuthKitBypass(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(12 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ FFInstallAuthKitBypass(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ FFInstallAuthKitBypass(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ FFInstallSwizzle(); FFInstallEspBypass(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ FFInstallSwizzle(); FFInstallEspBypass(); });
}
