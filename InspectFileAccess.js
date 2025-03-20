
/*
 * Title: InspectFileAccess
 *
 * Description: This script shows what files are loaded by the application during runtime by checking if the file exists (fileExistsAtPath).
 * The script excludes listing images however you can customise the exclusion filter to your desire
 * 
 * Run with frida -l InspectFileAccess.js -f <<APP-IDENTIFIER>>
 *
 */

Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        var fileExt = ObjC.Object(args[2]).toString()
        var exclusionFilter = !(fileExt.includes(".png") || 
                        fileExt.includes(".jpg") || 
                        fileExt.includes(".jpeg")            
                    )

        if (exclusionFilter){
            console.log('open' , ObjC.Object(args[2]).toString());
        }
    }
});
