/**
 * hook demo
 **/
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
if (android_dlopen_ext != null) {
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function (args) {
            this.hook = false;
            var soName = args[0].readCString();
            if (soName.indexOf("libmtguard.so") !== -1) {
                this.hook = true;
            }
        },
        onLeave: function (retval) {
            if (this.hook) {
                var jniOnload = Module.findExportByName("libmtguard.so", "JNI_OnLoad");
                Interceptor.attach(jniOnload, {
                    onEnter: function (args) {
                        console.log("Enter Mtguard JNI OnLoad");
                    },
                    onLeave: function (retval) {
                        console.log("After Mtguard JNI OnLoad");
                        hook_mtso();
                    }
                });
            }
        }
    });
}

var obj = null;
function hook_mtso(){
    var base_addr = Module.findBaseAddress("libmtguard.so");
    var real_addr = base_addr.add(0x414d);
    var clazz = null;

    Java.perform(function(){
        clazz = Java.use("java.lang.Object");
        Interceptor.attach(real_addr, {
            onEnter: function(args){
                console.log("arg2: "+args[2]);
                // 
                const length = Java.vm.getEnv().getObjectArrayLength(args[3]);
                console.log("Object[] length: ", length);
                for(var i=0;i<length,i++){
                    obj = Java.vm.getEnv().getObjectArrayElement(args[3], i);
                    console.log(obj);
                    if(!"0x0".equals(obj)){
                        var oneElement = Java.case(obj, clazz);
                        console.log("第 " +i +"个: "+oneElement);
                    }
                }

            },
            onLeave: function(retval){
                var result = Java.vm.getEnv().getObjectArrayElement(retval, 0);
                console.log("result: " + Java.case(result, clazz));
            }
        });


    });

}