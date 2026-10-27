//! JNI entry points for the Android app (`net.aegis.app.Native`).
//! Each takes and returns strings; results are the JSON of the matching
//! crate function.

use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
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
pub extern "system" fn Java_net_aegis_app_Native_enroll(
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
pub extern "system" fn Java_net_aegis_app_Native_servers(
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
pub extern "system" fn Java_net_aegis_app_Native_select(
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
pub extern "system" fn Java_net_aegis_app_Native_forget(
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
pub extern "system" fn Java_net_aegis_app_Native_vpnConfig(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let v = crate::vpn_config();
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_net_aegis_app_Native_start(
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
pub extern "system" fn Java_net_aegis_app_Native_stop(mut env: JNIEnv, _class: JClass) -> jstring {
    let v = crate::stop();
    ret(&mut env, v)
}

#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_net_aegis_app_Native_status(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let v = crate::status();
    ret(&mut env, v)
}
