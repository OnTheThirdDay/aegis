//! JNI entry points for the Android app (`borne.aegis.app.Native`).
//! Each takes and returns strings; results are the JSON of the matching
//! crate function.

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;
use serde_json::Value;

fn arg(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(Into::into).unwrap_or_default()
}

fn ret(env: &mut JNIEnv, v: Value) -> jstring {
    env.new_string(v.to_string())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_enroll(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
    code: JString,
) -> jstring {
    let (dir, code) = (arg(&mut env, &dir), arg(&mut env, &code));
    let v = crate::enroll(&dir, &code);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_servers(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) -> jstring {
    let dir = arg(&mut env, &dir);
    let v = crate::servers(&dir);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_select(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
    id: JString,
) -> jstring {
    let (dir, id) = (arg(&mut env, &dir), arg(&mut env, &id));
    let v = crate::select(&dir, &id);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_forget(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
    id: JString,
) -> jstring {
    let (dir, id) = (arg(&mut env, &dir), arg(&mut env, &id));
    let v = crate::forget(&dir, &id);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_vpnConfig(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let v = crate::vpn_config();
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_start(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
    fd: jint,
) -> jstring {
    let dir = arg(&mut env, &dir);
    let v = crate::start(&dir, fd);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_stop(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let v = crate::stop();
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_status(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let v = crate::status();
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_checkUpdate(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) -> jstring {
    let dir = arg(&mut env, &dir);
    let v = crate::check_update(&dir);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_downloadUpdate(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
    into: JString,
) -> jstring {
    let (dir, into) = (arg(&mut env, &dir), arg(&mut env, &into));
    let v = crate::download_update(&dir, &into);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_diagStart(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
    minutes: jint,
    about: JString,
) -> jstring {
    let (dir, about) = (arg(&mut env, &dir), arg(&mut env, &about));
    let v = crate::diag::start(&dir, u64::try_from(minutes).unwrap_or(0), &about);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_diagStop(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
    send: jboolean,
) -> jstring {
    let dir = arg(&mut env, &dir);
    let v = crate::diag::stop(&dir, send != 0);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_diagSend(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) -> jstring {
    let dir = arg(&mut env, &dir);
    let v = crate::diag::send_now(&dir);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_diagSave(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) -> jstring {
    let dir = arg(&mut env, &dir);
    let v = crate::diag::save(&dir);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_diagDiscard(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) -> jstring {
    let dir = arg(&mut env, &dir);
    let v = crate::diag::discard(&dir);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_diagNote(
    mut env: JNIEnv,
    _class: JClass,
    text: JString,
) -> jstring {
    let text = arg(&mut env, &text);
    let v = crate::diag::note(&text);
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_borne_aegis_app_Native_diagStatus(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) -> jstring {
    let dir = arg(&mut env, &dir);
    let v = crate::diag::status(&dir);
    ret(&mut env, v)
}
