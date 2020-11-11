
Java.perform(function () {

	var fileOutputStream = Java.use("java.io.FileOutputStream");

    fileOutputStream.$init
    	.overload('java.io.File', 'boolean')
    	.implementation = function (name, append) {

    		console.log(name)

    		return this.$init(name, append)
    		
    	}

});

// sg.vp.owasp_mobile.omtg_android