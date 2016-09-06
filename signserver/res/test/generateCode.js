#!/usr/bin/env gjs

/*
 * Run this script:
 * ./generateCode.js <number of lines>
 * to generate C code for generating a large binary
 * each line takes up 20 bytes
 */

function generateData(lines) {
	print('static char data[] = {');
	for (let i = 0; i < lines; i++) {
		print('42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42');
		if (i !== lines - 1)
			print(',');
	}
	print('};');
	print('');
}

function generateHeader(lines) {
	print('#include <stdio.h>');
	print('');
	generateData(lines);
	print('int main(void)');
	print('{');
}

function generateFooter() {
	print('}');
}

function main(args) {
	let lines = args[0];

	generateHeader(lines);
	print('  int i;');
	print('  for (i = 0; i < ' + lines + '* 20; i++) {');
	print('      printf("%c\\n", data[i]);');
	print('  }');
  print('  getchar();');
	generateFooter();
}

main(ARGV);

