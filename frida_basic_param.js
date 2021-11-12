// 参数转换 声明

/**
 * 基本类型
 * 
 **/ 
function basicType(){

	// string
	var jstring = Java.use("java.lang.String");
	// stringarray frida小于 14 版本
	var stringArray = Java.array("java.lang.String", [jstring.$new("a")]);
	// stringarray frida大于 14 版本
	var stringArray_ = Java.array("Ljava.lang.String;", [jstring.$new("a")]);


}


/**
 * 对象类型
 * 
 **/
function objectType(){
	
	//将当前线程附加到JavaVM，获取JNIEnv对象
	//区别：env:如果当前线程的JNIEnv 并未attach到vm 会抛出异常
	//     env1: 直接获取当前线程的包装对象
	var env = Java.vm.getEnv();
	var env1 = Java.vm.tryGetEnv();

}