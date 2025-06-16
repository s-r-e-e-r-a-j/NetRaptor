import os
choice = input('[+] to install press (Y) to uninstall press (N) >> ')
run = os.system
if str(choice) =='Y' or str(choice)=='y':

    run('chmod 755 netraptor.py')
    run('mkdir /usr/share/netraptor')
    run('cp netraptor.py /usr/share/netraptor/netraptor.py')

    cmnd=(' #! /bin/sh \n exec python3 /usr/share/netraptor/netraptor.py "$@"')
    with open('/usr/bin/netraptor','w')as file:
        file.write(cmnd)
    run('chmod +x /usr/bin/netraptor & chmod +x /usr/share/netraptor/netraptor.py')
    print('''\n\ncongratulation netraptor is installed successfully \nfrom now just type \x1b[6;30;42mnetraptor\x1b[0m in terminal ''')
if str(choice)=='N' or str(choice)=='n':
    run('rm -r /usr/share/netraptor ')
    run('rm /usr/bin/netraptor ')
    print('[!] now netraptor  has been removed successfully')
