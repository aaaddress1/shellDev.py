/* Beep & Alert.
 * by aaaddress1@chroot.org
 */
#include <shellDev>

void shellFunc shellEntry(void) {
    PVOID addr;

	fetchAPI(msgbox, MessageBoxA);
	fetchAPI(bp, Beep);

	bp(100, 100);
	msgbox(0, "hello", "word", 0);
}