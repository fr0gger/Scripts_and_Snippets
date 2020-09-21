from __future__ import print_function
import frida
import sys
import psutil


def checkIfProcessRunning(processName):
    '''
    Check if there is any running process that contains the given name processName.
    '''
    #Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False;
	

def on_message(message, data):
    print(message)
	

def main(proc):
    if checkIfProcessRunning(proc):
        print('[+] Process %s is running!' % proc)
        session = frida.attach(proc)

    else:
        print('[!] Process %s was not running!' % proc)
        print('[+] Running process %s!' % proc)
        session = frida.spawn(proc)
        session = frida.attach(proc)


    '''print(type(session))'''
    script = session.create_script("""
	
					   var Mutex_addr = Module.findExportByName("kernel32.dll", "CreateMutexA")
					   console.log('[+] CreateMutex addr: ' + Mutex_addr);
					   Interceptor.attach(Mutex_addr,
					   {
							onEnter: function (args) 
							{
								console.log("[+] Entering to createMutex")
								console.log('[+] lpName: ' + Memory.readUtf8String(args[2]));
							
							},
							onLeave: function (retval)
							{
							
							}
						});
 
                  """)

    script.on('message', on_message)
    script.load()
    try:
        frida.resume(proc)
    except:
        pass
    sys.stdin.read()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <process name or PID>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
		
    main(target_process)
