
#pragma once

bool bValid = false;

#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "GHr_Ryuuka/Tools/curl/json.hpp"
#include "GHr_Ryuuka/Tools/StrEnc.h"


JavaVM *jvm;
JNIEnv *genv;

struct MemoryStruct {
char *memory;
size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
size_t realsize = size * nmemb;
struct MemoryStruct *mem = (struct MemoryStruct *) userp;

mem->memory = (char *) realloc(mem->memory, mem->size + realsize + 1);
if (mem->memory == NULL) {
return 0;
}
memcpy(&(mem->memory[mem->size]), contents, realsize);
mem->size += realsize;
mem->memory[mem->size] = 0;
return realsize;
}

const char *GetUUID(JNIEnv *env, const char *uuid) {
jclass uuidClass = env->FindClass(/*java/util/UUID*/ StrEnc("B/TxJ=3BZ_]SFx","\x28\x4E\x22\x19\x65\x48\x47\x2B\x36\x70\x08\x06\x0F\x3C", 14).c_str());

auto len = strlen(uuid);

jbyteArray myJByteArray = env->NewByteArray(len);
env->SetByteArrayRegion(myJByteArray, 0, len, (jbyte *) uuid);

jmethodID nameUUIDFromBytesMethod = env->GetStaticMethodID(uuidClass, /*nameUUIDFromBytes*/ StrEnc("P6LV|'0#A+zQmoat,","\x3E\x57\x21\x33\x29\x72\x79\x67\x07\x59\x15\x3C\x2F\x16\x15\x11\x5F", 17).c_str(), /*([B)Ljava/util/UUID;*/ StrEnc("sW[\"Q[W3,7@H.vT0) xB","\x5B\x0C\x19\x0B\x1D\x31\x36\x45\x4D\x18\x35\x3C\x47\x1A\x7B\x65\x7C\x69\x3C\x79", 20).c_str());
jmethodID toStringMethod = env->GetMethodID(uuidClass, /*toString*/ StrEnc("2~5292eW","\x46\x11\x66\x46\x4B\x5B\x0B\x30", 8).c_str(), /*()Ljava/lang/String;*/ StrEnc("P$BMc' #j?<:myTh_*h0","\x78\x0D\x0E\x27\x02\x51\x41\x0C\x06\x5E\x52\x5D\x42\x2A\x20\x1A\x36\x44\x0F\x0B", 20).c_str());

auto obj = env->CallStaticObjectMethod(uuidClass, nameUUIDFromBytesMethod, myJByteArray);
auto str = (jstring) env->CallObjectMethod(obj, toStringMethod);
return env->GetStringUTFChars(str, 0);
}

const char *GetAndroidID(JNIEnv *env, jobject context) {
jclass contextClass = env->FindClass(/*android/content/Context*/ StrEnc("`L+&0^[S+-:J^$,r9q92(as", "\x01\x22\x4F\x54\x5F\x37\x3F\x7C\x48\x42\x54\x3E\x3B\x4A\x58\x5D\x7A\x1E\x57\x46\x4D\x19\x07", 23).c_str());
jmethodID getContentResolverMethod = env->GetMethodID(contextClass, /*getContentResolver*/ StrEnc("E8X\\7r7ys_Q%JS+L+~", "\x22\x5D\x2C\x1F\x58\x1C\x43\x1C\x1D\x2B\x03\x40\x39\x3C\x47\x3A\x4E\x0C", 18).c_str(), /*()Landroid/content/ContentResolver;*/ StrEnc("8^QKmj< }5D:9q7f.BXkef]A*GYLNg}B!/L", "\x10\x77\x1D\x2A\x03\x0E\x4E\x4F\x14\x51\x6B\x59\x56\x1F\x43\x03\x40\x36\x77\x28\x0A\x08\x29\x24\x44\x33\x0B\x29\x3D\x08\x11\x34\x44\x5D\x77", 35).c_str());
jclass settingSecureClass = env->FindClass(/*android/provider/Settings$Secure*/ StrEnc("T1yw^BCF^af&dB_@Raf}\\FS,zT~L(3Z\"", "\x35\x5F\x1D\x05\x31\x2B\x27\x69\x2E\x13\x09\x50\x0D\x26\x3A\x32\x7D\x32\x03\x09\x28\x2F\x3D\x4B\x09\x70\x2D\x29\x4B\x46\x28\x47", 32).c_str());
jmethodID getStringMethod = env->GetStaticMethodID(settingSecureClass, /*getString*/ StrEnc("e<F*J5c0Y", "\x02\x59\x32\x79\x3E\x47\x0A\x5E\x3E", 9).c_str(), /*(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;*/ StrEnc("$6*%R*!XO\"m18o,0S!*`uI$IW)l_/_knSdlRiO1T`2sH|Ouy__^}%Y)JsQ:-\"(2_^-$i{?H", "\x0C\x7A\x4B\x4B\x36\x58\x4E\x31\x2B\x0D\x0E\x5E\x56\x1B\x49\x5E\x27\x0E\x69\x0F\x1B\x3D\x41\x27\x23\x7B\x09\x2C\x40\x33\x1D\x0B\x21\x5F\x20\x38\x08\x39\x50\x7B\x0C\x53\x1D\x2F\x53\x1C\x01\x0B\x36\x31\x39\x46\x0C\x15\x43\x2B\x05\x30\x15\x41\x43\x46\x55\x70\x0D\x59\x56\x00\x15\x58\x73", 71).c_str()); // @ERROLDEC
auto obj = env->CallObjectMethod(context, getContentResolverMethod);
auto str = (jstring) env->CallStaticObjectMethod(settingSecureClass, getStringMethod, obj, env->NewStringUTF(/*android_id*/ StrEnc("ujHO)8OfOE", "\x14\x04\x2C\x3D\x46\x51\x2B\x39\x26\x21", 10).c_str()));
return env->GetStringUTFChars(str, 0);
}
const char *GetDeviceModel(JNIEnv *env) {
jclass buildClass = env->FindClass(/*android/os/Build*/ StrEnc("m5I{GKGWBP-VOxkA", "\x0C\x5B\x2D\x09\x28\x22\x23\x78\x2D\x23\x02\x14\x3A\x11\x07\x25", 16).c_str());
jfieldID modelId = env->GetStaticFieldID(buildClass, /*MODEL*/ StrEnc("|}[q:", "\x31\x32\x1F\x34\x76", 5).c_str(), /*Ljava/lang/String;*/ StrEnc(".D:C:ETZ1O-Ib&^h.Y", "\x62\x2E\x5B\x35\x5B\x6A\x38\x3B\x5F\x28\x02\x1A\x16\x54\x37\x06\x49\x62", 18).c_str()); // @ERROLDEC
auto str = (jstring) env->GetStaticObjectField(buildClass, modelId);
return env->GetStringUTFChars(str, 0);
}
const char *GetDeviceBrand(JNIEnv *env) {
jclass buildClass = env->FindClass(/*android/os/Build*/ StrEnc("0iW=2^>0zTRB!B90", "\x51\x07\x33\x4F\x5D\x37\x5A\x1F\x15\x27\x7D\x00\x54\x2B\x55\x54", 16).c_str());
jfieldID modelId = env->GetStaticFieldID(buildClass, /*BRAND*/ StrEnc("@{[FP", "\x02\x29\x1A\x08\x14", 5).c_str(), /*Ljava/lang/String;*/ StrEnc(".D:C:ETZ1O-Ib&^h.Y", "\x62\x2E\x5B\x35\x5B\x6A\x38\x3B\x5F\x28\x02\x1A\x16\x54\x37\x06\x49\x62", 18).c_str()); // @ERROLDEC
auto str = (jstring) env->GetStaticObjectField(buildClass, modelId);
return env->GetStringUTFChars(str, 0);
}
const char *GetPackageName(JNIEnv *env, jobject context) {
jclass contextClass = env->FindClass(/*android/content/Context*/ StrEnc("`L+&0^[S+-:J^$,r9q92(as", "\x01\x22\x4F\x54\x5F\x37\x3F\x7C\x48\x42\x54\x3E\x3B\x4A\x58\x5D\x7A\x1E\x57\x46\x4D\x19\x07", 23).c_str());
jmethodID getPackageNameId = env->GetMethodID(contextClass, /*getPackageName*/ StrEnc("YN4DaP)!{wRGN}", "\x3E\x2B\x40\x14\x00\x33\x42\x40\x1C\x12\x1C\x26\x23\x18", 14).c_str(), /*()Ljava/lang/String;*/ StrEnc("VnpibEspM(b]<s#[9cQD", "\x7E\x47\x3C\x03\x03\x33\x12\x5F\x21\x49\x0C\x3A\x13\x20\x57\x29\x50\x0D\x36\x7F", 20).c_str()); // @ERROLDEC
auto str = (jstring) env->CallObjectMethod(context, getPackageNameId);
return env->GetStringUTFChars(str, 0);
}
const char *GetDeviceUniqueIdentifier(JNIEnv *env, const char *uuid) {
jclass uuidClass = env->FindClass(/*java/util/UUID*/ StrEnc("B/TxJ=3BZ_]SFx", "\x28\x4E\x22\x19\x65\x48\x47\x2B\x36\x70\x08\x06\x0F\x3C", 14).c_str());
auto len = strlen(uuid);
jbyteArray myJByteArray = env->NewByteArray(len);
env->SetByteArrayRegion(myJByteArray, 0, len, (jbyte *) uuid);
jmethodID nameUUIDFromBytesMethod = env->GetStaticMethodID(uuidClass, /*nameUUIDFromBytes*/ StrEnc("P6LV|'0#A+zQmoat,", "\x3E\x57\x21\x33\x29\x72\x79\x67\x07\x59\x15\x3C\x2F\x16\x15\x11\x5F", 17).c_str(), /*([B)Ljava/util/UUID;*/ StrEnc("sW[\"Q[W3,7@H.vT0) xB", "\x5B\x0C\x19\x0B\x1D\x31\x36\x45\x4D\x18\x35\x3C\x47\x1A\x7B\x65\x7C\x69\x3C\x79", 20).c_str());
jmethodID toStringMethod = env->GetMethodID(uuidClass, /*toString*/ StrEnc("2~5292eW", "\x46\x11\x66\x46\x4B\x5B\x0B\x30", 8).c_str(), /*()Ljava/lang/String;*/ StrEnc("P$BMc' #j?<:myTh_*h0", "\x78\x0D\x0E\x27\x02\x51\x41\x0C\x06\x5E\x52\x5D\x42\x2A\x20\x1A\x36\x44\x0F\x0B", 20).c_str());
auto obj = env->CallStaticObjectMethod(uuidClass, nameUUIDFromBytesMethod, myJByteArray);
auto str = (jstring) env->CallObjectMethod(obj, toStringMethod);
return env->GetStringUTFChars(str, 0);
}

// Global variables

std::string Login(const char *user_key) {
    if (user_key == nullptr || strlen(user_key) == 0) {
        return "Please enter a license key";
    }
    
    JNIEnv *env;
    jvm->AttachCurrentThread(&env, 0);

    // Get Android application context
    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    jmethodID currentActivityThreadMethod = env->GetStaticMethodID(activityThreadClass, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject activityThread = env->CallStaticObjectMethod(activityThreadClass, currentActivityThreadMethod);
    
    jmethodID getApplicationMethod = env->GetMethodID(activityThreadClass, "getApplication", "()Landroid/app/Application;");
    jobject context = env->CallObjectMethod(activityThread, getApplicationMethod);

    // Generate device ID
    std::string android_id = GetAndroidID(env, context);
    std::string model = GetDeviceModel(env);
    std::string brand = GetDeviceBrand(env);
    
    // Create unique device identifier
    std::string hwid = android_id + model + brand;
    std::string device_id = GetDeviceUniqueIdentifier(env, hwid.c_str());
    
    jvm->DetachCurrentThread();

    // Prepare CURL request
    CURL *curl = curl_easy_init();
    std::string response_str;
    
    if (curl) {
        // Use your domain
        std::string url = "http://yourdomain/api.php?action=verify";
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        // Set headers
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        // Prepare POST data
        char post_data[512];
        sprintf(post_data, "license=%s&device=%s&game=FREEFIRE", 
                user_key, device_id.c_str());
        
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        
        // Response handler
        MemoryStruct chunk;
        chunk.memory = (char*)malloc(1);
        chunk.size = 0;
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
        
        // Disable SSL verification for HTTP
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        // Execute request
        CURLcode res = curl_easy_perform(curl);
        
        if (res == CURLE_OK) {
            response_str = std::string(chunk.memory, chunk.size);
            
            try {
                // Parse JSON response
                json result = json::parse(chunk.memory);
                
                if (result.contains("status") && result["status"] == true) {
                    // SUCCESS: License is valid
                    if (result.contains("data") && result["data"].contains("token")) {
                        g_Token = result["data"]["token"].get<std::string>();
                        bValid = true;
                        
                        // Build success message
                        std::string success_msg = "SUCCESS! ";
                        
                        if (result["data"].contains("modname")) {
                            success_msg += result["data"]["modname"].get<std::string>();
                            success_msg += " | ";
                        }
                        
                        if (result["data"].contains("expiry")) {
                            success_msg += result["data"]["expiry"].get<std::string>();
                            success_msg += " | ";
                        }
                        
                        if (result["data"].contains("credit")) {
                            success_msg += result["data"]["credit"].get<std::string>();
                        }
                        
                        return success_msg;
                    }
                } else {
                    // FAILURE: License is invalid
                    bValid = false;
                    if (result.contains("reason")) {
                        return "ERROR: " + result["reason"].get<std::string>();
                    } else {
                        return "ERROR: Invalid license key";
                    }
                }
            } catch (json::exception &e) {
                bValid = false;
                return "JSON Parse Error: " + std::string(e.what());
            }
        } else {
            bValid = false;
            return "Network Error: " + std::string(curl_easy_strerror(res));
        }
        
        // Cleanup
        if (chunk.memory) free(chunk.memory);
        if (headers) curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        return "Failed to initialize network connection";
    }
    
    return "Unknown error occurred";
}

// Simple verification function
bool VerifyLicenseKey(const char* license_key) {
    std::string result = Login(license_key);
    return bValid;
}

// Simplified clipboard function
std::string getClipboard() {
    std::string result;
    JNIEnv *env;
    
    jvm->AttachCurrentThread(&env, NULL);
    
    // Get application context
    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    jmethodID currentActivityThreadMethod = env->GetStaticMethodID(activityThreadClass, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject activityThread = env->CallStaticObjectMethod(activityThreadClass, currentActivityThreadMethod);
    
    jmethodID getApplicationMethod = env->GetMethodID(activityThreadClass, "getApplication", "()Landroid/app/Application;");
    jobject context = env->CallObjectMethod(activityThread, getApplicationMethod);
    
    // Get clipboard service
    jclass contextClass = env->FindClass("android/content/Context");
    jmethodID getSystemServiceMethod = env->GetMethodID(contextClass, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    
    jstring serviceName = env->NewStringUTF("clipboard");
    jobject clipboardManager = env->CallObjectMethod(context, getSystemServiceMethod, serviceName);
    env->DeleteLocalRef(serviceName);
    
    if (clipboardManager) {
        jclass clipboardClass = env->FindClass("android/content/ClipboardManager");
        jmethodID getTextMethod = env->GetMethodID(clipboardClass, "getText", "()Ljava/lang/CharSequence;");
        
        jobject textObj = env->CallObjectMethod(clipboardManager, getTextMethod);
        
        if (textObj) {
            jclass charSequenceClass = env->FindClass("java/lang/CharSequence");
            jmethodID toStringMethod = env->GetMethodID(charSequenceClass, "toString", "()Ljava/lang/String;");
            
            jstring textStr = (jstring)env->CallObjectMethod(textObj, toStringMethod);
            
            if (textStr) {
                const char* text = env->GetStringUTFChars(textStr, 0);
                if (text) {
                    result = text;
                    env->ReleaseStringUTFChars(textStr, text);
                }
                env->DeleteLocalRef(textStr);
            }
            env->DeleteLocalRef(textObj);
        }
        
        env->DeleteLocalRef(clipboardClass);
        env->DeleteLocalRef(clipboardManager);
    }
    
    env->DeleteLocalRef(contextClass);
    env->DeleteLocalRef(activityThreadClass);
    
    jvm->DetachCurrentThread();
    
    return result;
}
