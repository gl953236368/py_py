/**
 *  对 目标so jni load执行前 进行操作
 * android_dlopen_ext方法，来实现动态库的加载，
 * 返回dlextinfo，而非android的，则是调用dlopen加载的
 **/ 
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
if(android_dlopen_ext != null){
	Interceptor.attach(android_dlopen_ext, {
		onEnter: function(args){
			this.hook = false;
			var soName = args[0].readCString();
			if(soName.indexOf("libsgmainso-6.5.24.so") >= 0){
				this.hook = true;
			}
		},
		onLeave: function(retval){
			if(this.hook){
				// 拦截到目标so 此时装载进内存，执行完init函数，但jni onload还没执行
				var jniLoad = Module.findExportByName("libsgmainso-6.5.24.so", "JNI_Onload");
				Interceptor.attach(jniLoad, {
					onEnter: function(args){
						// 执行 JNI load前
						console.log("进入 目标 so的 jni执行前");
					},
					onLeave: function(retval){
						// JNI Onload 执行完时机
						console.log("执行后");
						hook_docommand();
					}
				})
			}
		}
	});
}


function hook_docommand(){
	// 切换类加载器 
	Java.perform(function(){
		Java.enumerateClassLoaders({
			onMatch: function(loader){
				try{
					if(loader.findClass("com.taobao.wireless.security.adapter.JNICLibrary")){
						console.log("Success found loader");
						console.log(loader);
						Java.classFactory.loader = loader;
					}
				}catch(error){
					console.log("find error: ", error);
				}
			},
			onComplete: function(){
				console.log("over");
			}

		});

		// 操作java层
		Java.use("com.taobao.wireless.security.adapter.JNICLibrary").doCommandNative.implementation = function(arg_int, arg_array) {
            // call70102Native()
            var result = this.doCommandNative(arg_int,arg_array);
            console.log("args:"+arg_int, arg_array)
            console.log("return:"+result)
            // call70102();
            return result;
        }
		
	});
}


// CALL From JAVA 主动调用java层
function call70102(){
    var Intger = Java.use("java.lang.Integer");
    var jstring = Java.use("java.lang.String");
    var Boolean = Java.use("java.lang.Boolean");

    var input0 = jstring.$new("23867946")
    var input1 = jstring.$new("YG1zUNfVgh8DAFUx0fP7cSZP&&&23867946&88c29b8793d3b1d7500437a8dae998cc&1621807015&mtop.lazada.usergrowth.multiorder.getpoplayerconfigandvoucher&1.0&&600000@lazada_android_6.74.0&&&&&27&&&&&&&")
    var input2 = Boolean.$new(false);
    var input3 = Intger.$new(0);
    var input4 = jstring.$new("mtop.lazada.usergrowth.multiorder.getpoplayerconfigandvoucher")
    var input5 = jstring.$new("pageId=&pageName=");
    var argList = Java.array("Ljava.lang.Object;", [input0,input1,input2,input3,input4,input5,null,null,null])
    console.log("尝试主动调用70102");
    console.log("result is >>>>> ", Java.use("com.taobao.wireless.security.adapter.JNICLibrary").doCommandNative(70102, argList))
}



// Call From Native 主动调用native
function call70102Native(){
    Java.perform(function() {
        var base_addr = Module.findBaseAddress("libsgmainso-6.5.24.so");
        // 调用方法地址
        var real_addr = base_addr.add(0xcc51)
        var docommand = new NativeFunction(real_addr, "pointer", ["pointer", "pointer", "int", "pointer"]);

        var JNIEnv = Java.vm.getEnv();
        // 不切换加载器找不到这个类，我觉得这个操作可能会耽误时间。直接给null吧，反正一般用不到
        // const handle = JNIEnv.findClass('com/taobao/wireless/security/adapter/JNICLibrary')
        // const obj = JNIEnv.allocObject(handle);
        // 如果是一个静态函数，传jclazz，也可以如下这么传
        // var yourclass = Java.use("a.b.c.d");
        // var jclazz = yourclass.class.$handle

        var Intger = Java.use("java.lang.Integer");
        var jstring = Java.use("java.lang.String");
        var Boolean = Java.use("java.lang.Boolean");

        var cla = JNIEnv.findClass("java/lang/Object");
        // 声明objet list
        var argList = JNIEnv.newObjectArray(9, cla, ptr(0));
        var input0 = JNIEnv.newStringUtf('23867946');
        var input1 = JNIEnv.newStringUtf('YG1zUNfVgh8DAFUx0fP7cSZP&&&23867946&88c29b8793d3b1d7500437a8dae998cc&1621807015&mtop.lazada.usergrowth.multiorder.getpoplayerconfigandvoucher&1.0&&600000@lazada_android_6.74.0&&&&&27&&&&&&&');
        
        var input2 = Boolean.$new(false);
        var input3 = Intger.$new(0);
        var input4 = jstring.$new("mtop.lazada.usergrowth.multiorder.getpoplayerconfigandvoucher")
        var input5 = jstring.$new("pageId=&pageName=");

        JNIEnv.setObjectArrayElement(argList, 0, input0);
        JNIEnv.setObjectArrayElement(argList, 1, input1);

        JNIEnv.setObjectArrayElement(argList, 2, input2.$h);
        JNIEnv.setObjectArrayElement(argList, 3, input3.$h);
        JNIEnv.setObjectArrayElement(argList, 4, input4.$h);
        JNIEnv.setObjectArrayElement(argList, 5, input5.$h);

        JNIEnv.setObjectArrayElement(argList, 6, ptr(0));
        JNIEnv.setObjectArrayElement(argList, 7, ptr(0));
        JNIEnv.setObjectArrayElement(argList, 8, ptr(0));


        var point = docommand(JNIEnv.handle, ptr(0), 70102, argList);
        var obj = Java.use("java.lang.Object");
        var s = Java.cast(point, obj);
        console.log("result:" + s);
        // console.log(Java.vm.tryGetEnv().getStringUtfChars(point).readCString());
    })
}



