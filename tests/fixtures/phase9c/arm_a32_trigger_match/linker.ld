/* Documentation-equivalent layout for the deterministic Python generator. */
ENTRY(synthetic_trigger_function)
SECTIONS
{
  . = 0x00010000;
  .text : { *(.text) }
  . = 0x00020000;
  .data : { *(.data) }
}
