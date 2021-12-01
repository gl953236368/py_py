/** 
 *  hook init_array 
 * 打印对应的函数偏移地址
 * 
 * **/
function hook_init_array(){
	if(Process.pointerSize == 4){
		var linker = Process.findModuleByName("linker");
	}else if(Process.pointerSize == 8){
		var linker = Process.findModuleByName("linker64");
	}

	var add_call_array = null;
	if(linker){
		var symbols = linker.enumerateSymbols();
		for(var i = 0; i < symbols.length, i++){
			if(name.indexOf("call_array") >= 0){
				addr_call_array = symbols[i].address;
			}
		}
		
	}

	if(addr_call_array){
		Interceptor.attach(addr_call_array, {
			onEnter:function(args){
				// console.log(args[0], args[1], args[2]);
				this.type = ptr(args[0]).readCString();
				if(this.type == "DT_INIT_ARRAY"){
					this.count = args[2];
					this.path = ptr(args[3]).readCString();
					var strs = new Array();
					strs = this.path.split('/'); 
					this.fileName = strs.pop();
					if(this.count > 0){
						console.log("path: ", this.path);
						console.log("fileName: ", this.fileName);
					}
					for(var i=0;i<this.count; i++){
						console.log("offset: init_array["+ i +"] =", 
							ptr(args[1])
							.add(Process.pointerSize*i)
							.readPointer()
							.sub(Module.findBaseAddress(this.fileName)));
					}


				}
			},
			onLeave:function(retval){}
		});
	}
}

/**
 * 主动调用native 对context参数对象化的转变
 * 
 * 
 **/
function callHWithOutJNIOnLoad(){
	Java.perform(function(){
		var base_addr = Module.findBaseAddress("libsoulpower.so");
        var real_addr = base_addr.add(0xaa73c);
        var h = new NativeFunction(real_addr, "pointer", ["pointer", "pointer","pointer","int", "pointer","pointer",]);
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        var context = currentApplication.getApplicationContext();

        var input3 = "/mobile/app/version/query?bi=[\"179bcc867dc\",46000,\"Xiaomi\",\"Android\",29,10,\"MIX2S\",\"Xiaomi\",440,\"1080*2030\",\"yyb\",\"2G\",\"zh_CN\"]&bik=32755&triggerType=2&uid=RUszamUzMVM5Yms9";
        var input4 = "cn.soulapp.android/b25cff Mozilla/5.0 (Linux; Android 10; MIX 2S Build/QKQ1.190828.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.101 Mobile Safari/537.3610000003179bcc867e63.83.0YLNlPD4Fbn0DABXvNNKKrxdDTUlYIDJTNjcM4TIjdMBTjg__0db56ccba44f8df2bce77e6ba99b5ddbGk+E8AQOt/JJOPP9O2kHCVEhCn55oPDk";

        // 如何把context转换为jobject
        var point = h(Java.vm.tryGetEnv(), ptr(0), context.$h, 1622369920, Java.vm.tryGetEnv().newStringUtf(input3),Java.vm.tryGetEnv().newStringUtf(input4));
        console.log(Java.vm.tryGetEnv().getStringUtfChars(point).readCString());


	})


}
function main(){
	hook_init_array();
}
