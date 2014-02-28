laughing-batman
===============
An unfinished ruby disassembler for I386 written and tested with ruby 1.9.3p484 (2013-11-22) [i386-mingw32].

File structure is as follows:
<pre>
.
|-- lib
|   |-- definitions.rb
|   |-- disassembler.rb
|   `-- methods.rb
|-- LICENSE
|-- README.md
|-- testing
|   |-- ex2
|   |-- ex2.S
|   |-- example1.o
|   |-- example1.S
|   |-- example2.o
|   |-- example2.S
|   |-- test
|   |-- test2
|   |-- test2.S
|   `-- test.S
`-- VERSION.txt

</pre>

###Using laughing-batman

1. You have an assembled file: <pre> ./testing/example1.0;./testing/example2.0;./testing/ex2;./testing/test;./testing/test2 were assembled with nasm.</pre>
2. The file was created with the format seen in: <pre>./testing/example1.S;./testing/example2.S;./testing/ex2.S;./testing/test.S;./testing/test2.S</pre>
3. You run laughing-batman: <pre>ruby ./lib/disassembler.rb ./YOUR/ASSEMBLED/FILE/PATH </pre>
4. Results are printed to the screen

###How does it work?
<ul>
  <li>The <b>dissassembler.rb</b> file uses a Linear Sweep algorithm to disassemble the assembled file.</li>
  <li>The <b>definitions.rb</b> file provides definitions for the format of the instructions as well as the operand table from http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf</li>
  <li>The <b>methods.rb</b> file implements the parsing and analyzing of the opcodes.</li>
  </ul>
