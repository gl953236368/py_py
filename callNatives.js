/**
 * 主动调用 so 中native函数
 * 
 **/

function callNativeSign(){
	Java.perform(function(){
		var target_so = Module.findBaseAddress("libsign.so");
		var real_addr = target_so.add(0x38BF5);
		var nativeSign = new NativeFunction(real_addr, "pointer", ["pointer", "pointer", "pointer", "pointer", "int", "int", "pointer"]);

		var JNIEnv = Java.env.getEnv();
		// 获取当前 context
		var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
		var context = currentApplication.getApplicationContext();

		var arg_addr = Memory.alloc(7);
		Memory.writeByteArray(arg_addr, [0x76,0x65,0x72,0x73,0x69,0x6f,0x6e]);
		var jbyteArray = Java.vm.tryGetEnv().newByteArray(7);
		Java.vm.tryGetEnv().setByteArrayRegion(jbyteArray, 0, 7, arg_addr);
		// 参数 env， jclass ，jobject， 其他
		var pointer = nativeSign(JNIEnv.handle, ptr(0), ptr(context.$h), ptr(0), 0xc4917cb5, 0x17a, jbyteArray);
		console.log((Java.vm.tryGetEnv().getStringUtfChars(pointer).readCString());

	});
}