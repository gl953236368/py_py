// frida基础调用so 记录
//

/**
 * 枚举内存中的 so 文件
 * 用于观察目标 so 是否加载
 **/
function hook_native(){
	// Process.enumerateModules 获得所有加载的so文件
	var modules = Process.enumerateModules();
	for(var i in modules){
		var module = modules[i];
		console.log(module.name);
		if(module.name.indexOf("目标.so") > -1){
			console.log("获取目标so文件：" + module.name);
			console.log("目标so文件地址：" + module.base);
		}
	}
}

/**
 * 获取目标so文件的基地址
 * 
 **/
function hook_module(){
	var baseAddr = Module.findBaseAddress("目标.so");
	console.log("目标so文件地址：", baseAddr);
}

/**
 * 获取指定 so 文件的函数
 * 通过导出函数名定位 native 方法
 **/
function hook_func_from_exports(){
	var func_addr = Module.findExportByName("目标.so", "目标方法");
	console.log("目标方法地址:", func_addr);
}


/**
 * 获取指定 so 文件的函数
 * 通过 symbols 符号定位 native 方法
 **/
function hook_func_from_symbols(){
	// 获取目标 symbols的方法
	var NewStringUTF_addr = null;
	var symbols = Process.findModuleByName("libart.so").enuerateSymbols();
	for(var i in symbols){
		var symbol = symbols[i];
		if(symbol.name.indexOf("art") >=0 &&
			symbol.name.indexOf("JNI") >=0 &&
			symbol.name.indexOf("CheckJNI") < 0){
			if(symbol.name.indexOf("NewStringUTF") >=0 ){
				console.log("find symbos name:", symbol.name, "address is ", symbol.address);
				NewStringUTF_addr = symbols.address;
			}
		}
	}

	console.log("NewStringUTF_addr is ", NewStringUTF_addr);

	// 简单对方法进行 hook改写
	Interceptor.attach(NewStringUTF_addr, {
		onEnter: function(args){
			console.log("args 0 is ", args[0], "hexdump is ", hexdump(args[0]));
			console.log("args 1 is ", args[1], "hexdump is ", hexdump(args[1]));
			var env = Java.vm.tryGetEnv();
			if(env != null){
				// 直接读取 char
				console.log("Memory readCstring is ", Memory.readCstring(args[1]));
			}else {
				console.log("get env error");
			}
		},
		onLeave: function(retval){
			console.log("result is ", Java.case(retval, Java.use("java.lang.String")));
			var env = Java.vm.tryGetEnv();
			if(env != null){
				var jstring = env.newStringUTF("修改返回结果");
				retval.replace(ptr(jstring));
			}
		}
	})
}

/**
 * 获取指定 so 文件的函数
 * 通过地址偏移 inline-hook 任意函数
 **/
function hook_func_from_inline(){
	var target_so_addr = Module.findBaseAddress("libnative-lib.so");
	console.log("libnative-lib.so baseAddr is ", target_so_addr);
	if(target_so_addr){
		// 参数二为导出方法名 ida可查
		var add_addr1 = Module.findExportByName("libnative-lib.so", "_Z5r0addii");
		var add_addr2 = target_so_addr.add(0x94B2 + 1); // 32需要加1
		console.log(add_addr1);
		console.log(add_addr2);
	}


	// 主动调用
	var add1 = new NativeFunction(add_addr1, "int", ["int", "int"]);
	var add2 = new NativeFunction(add_addr2, "int", ["int", "int"]);

	console.log("add1 result is ", add1(10, 10));
	console.log("add2 result is ", add2(20, 20));
}

// 调用
// setImmediate(hook_func_from_inline);


/**
 * 通过 Intercept 拦截器打印 native 方法参数和返回值, 并修改返回值
 * 
 * onEnter: 函数(args) : 回调函数, 给定一个参数 args, 用于读取或者写入参数作为 NativePointer 对象的指针;
 * 
 * onLeave: 函数(retval) : 回调函数给定一个参数 retval, 该参数是包含原始返回值的 NativePointer 派生对象; 
 * 可以调用 retval.replace(1234) 以整数 1234 替换返回值, 或者调用retval.replace(ptr("0x1234")) 以替换为指针;
 * 
 * 注意: retval 对象会在 onLeave 调用中回收, 因此不要将其存储在回调之外使用, 
 * 如果需要存储包含的值, 需要制作深拷贝, 如 ptr(retval.toString())
 **/
function hook_and_rewrite_func_result(){
	var func_addr = Module.findExportByName("libnative-lib.so", "add_c");
	console.log("add_c baseAddr is ", func_addr);

	Interceptor.attach(func_addr, {
		onEnter: function(args){
			console.log("add_c called");
            console.log("arg1 is ",args[0].toInt32());
            console.log("arg2 is ", args[1].toInt32());
		},
		onLeave: function(retval){
            console.log("add_c result is ", retval.toInt32());
            retval.replace(100);
		}
	})
}

/**
 * 通过 Intercept 拦截器替换原方法
 * 
 * so层注册方法：new NativeFunction(address, returnType, argTypes[, options])
 * address : 函数地址；
 * returnType : 指定返回类型；
 * argTypes : 数组指定参数类型；
 * （类型可选: void, pointer, int, uint, long, ulong, char, uchar, 
 * float, double, int8, uint8, int16, int32, uint32, int64, uint64;）
 **/
 function hook_and_replace_func(){
 	Java.perform(function(){
 		// 这个c_getSum方法有两个int参数、返回结果为两个参数相加
 		// 这里用NativeFunction函数自己定义了一个c_getSum函数
 		var add_addr = Module.findExportByName("libtttt.so", "c_getNum");
 		var add_method = new NativeFunction(add_addr, "int", ["int", "int"]);
 		// 主动调用原始函数
 		console.log("result is ", add_method(1, 2));
 		
 		// 改写方法
 		Interceptor.replace(add_method, new NativeCallback(function(a, b){
 			// 改写 无论怎么传 都返回0
			return 0;
 		}, "int", ["int", "int"]));

 		// 再次调用
 		console.log("new result is ", add_method(1, 2));

 	});
 }

 /**
 * so层注册方法：new NativeFunction(address, returnType, argTypes[, options])
 * 
 * address : 函数地址；
 * returnType : 指定返回类型；
 * argTypes : 数组指定参数类型；
 * （类型可选: void, pointer, int, uint, long, ulong, char, uchar, 
 * float, double, int8, uint8, int16, int32, uint32, int64, uint64;）
 **/
 function invock_native_func(){
	// 1.
	var baseAddr = Module.findBaseAddress("libnative-lib.so");
	console.log("baseAddr is ", baseAddr);
	var offset = 0x0000A28C + 1;
	var add_c_func_addr = baseAddr.add(offset);
	var add_c_func = new NativeFunction(add_c_func_addr, "int", ["int", "int"]);
	var result = add_c_func(1, 2);
    console.log(result);

    // 2.
    Java.perform(function(){
    	// 获得目标so 地址
    	var baseAddr = Module.findBaseAddress("libnative-lib.so");
    	// 获得目标 so 中方法地址 thumb 需要 +1
    	var sub_834_addr = base.add(0x835);
    	// 声明方法 方法地址、返回值、参数列表
    	var sub_834_addr_func = new NativeFunction(sub_834_addr, "pointer", ["pointer"]);
    	// 开辟指针入参地址
    	var arg0 = Memory.allco(10);
    	// 地址写入目标值
    	ptr(arg0).writeUtf8String("123");
    	var result = sub_834_addr_func(arg0);
    	console.log("result is ", hexdump(result));
    });

}

/**
* hook libart 中的 jni 方法
* 
**/
function hook_libart(){
 	var GetStringUTFChars_addr = null;

 	// jni 系统函数都在 libart.so中
 	var module_libart = Process.findBaseAddress("libart.so");
 	var symbols = module_libart.enumerateSymbols();
 	for(var i = 0; i<symbols.length; i++){
 		var name = symbols[i].name;
 		if((name.indexOf("JNI") >= 0) &&
 			(name.indexOf("CheckJNI") == -1) &&
 			(name.indexOf("art") >= 0)){

 			if(name.indexOf("GetStringUTFChars") >= 0){
 				console.log(name);
 				// 获得指定的 jni方法
 				GetStringUTFChars_addr = symbols[i].address;
 			}
 		}
 	}

 	Java.perform(function(){
 		Interceptor.attach(GetStringUTFChars_addr, {
 			onEnter: function(args){
 				var env = Java.vm.tryGetEnv();
 				// console.log("args[0] is ", args[0]);
 				// console.log("args[1] is ", args[1]);
 				console.log("native args[1] is ", env.GetStringUTFChars(args[1], null).readCstring());
 				console.log("GetStringUTFChars onEnter called from: \n" +
 					Tread.backtrace(this.context, Backtracer.FUZZY)
 					.map(DebugSymbol.fromAddress)
 					.join("\n") + "\n");
 				// console.log("native args[1] is ", Java.case(args[1], Java.use("java.lang.String")));
 				// console.log("native args[1] is ", Memory.readCstring(env.GetStringUTFChars(args[1], null)));
 			},
 			onLeave: function(retval){
 				// return const char*
 				console.log("GetStringUTFChars onLeave: ", ptr(retval).readCstring());
 			}
 		})
 	});
 }

/**
* hook libc 中的系统方法
* 
* /system/lib(64)/libc.so 导出的符号没有进行 namemanline , 直接过滤筛选即可
**/
function hook_libc(){
	var pthread_create_addr = null;

	// 枚举加载的so文件
	// console.log(JSON.stringify(Process.enmurateModules));
	// Process.enumerateModules();

	// 枚举目标so里的func
	var symbols = Process.findModuleByName("libc.so").enumerateSymbols();
	for(var i = 0; i < symbols.length; i++){
		var name = symbols[i].name;
		if(name === "pthread_create"){
			console.log("symbols name is ", name);
			console.log("symbols address is ", symbols[i].address);
			pthread_create_addr = symbols[i].address;
		}
	}

	Interceptor.attach(pthread_create_addr, {
		onEnter: function(args){
			console.log("args is " + args[0], args[1], args[2],args[3]);
		},
		onLeave: function(retval){
			console.log(retval);
		}
	});

}

/**
* hook libc 中的系统方法
* 
* libc.so 中方法替换 hook 检测frida的函数
**/
function hook_and_replace_libc_func(){
	// var exports = Process.findModuleByName("libnative-lib.so").enumerateExports(); // 导出
	// var imports = Process.findModuleByName("libnative-lib.so").enumerateImports(); // 导入
	// var symbols = Process.findModuleByName("libnative-lib.so").enumerateSymbols(); // 符号

	var pthread_create_addr = null;
	var symbols = Process.getModuleByName("libc.so").enumerateSymbols();
	for(var i = 0; i < symbols.length; i++){
		var symbol = symbols[i];
		if(symbol.name === "pthread_create"){
			pthread_create_addr = symbol.address;
			console.log("symbols name is ", symbol.name);
			console.log("symbols address is ", symbol.address);
		}
	}

	Java.perform(function(){
		// 定义方法 之后主动调用
		var pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
		Interceptor.replace(pthread_create_addr, new NativeCallback(function(a0, a1, a2, a3){
			var result = null;
			var detect_frida_loop = Module.findExportByName("libnative-lib.so", "_Z17detect_frida_loopPv");
			console.log("a0,a1,a2,a3 ->",a0,a1,a2,a3);
			if(String(a2) === String(detect_frida_loop)){
				result = 0;
				console.log("阻止frida反调试启动");
			}else {
				result = pthread_create(a0, a1, a2, a3);
				console.log("正常启动");
			}
			return result;
		}), "int", ["pointer", "pointer", "pointer", "pointer"]);
	})

}

/**
* hook native 调用栈
* 
**/ 
function hook_stack(){
	// f 为目标方法的地址 
	Interceptor.attach(f, {
		onEnter: function(args){
			console.log("RegisterNatives called from:\n" + 
				Thread.Backtracer(this.context, Backtracer.ACCURATE)
				.map(DebugSymbol.fromAddress).json('\n') + '\n');
		}
	})
}





