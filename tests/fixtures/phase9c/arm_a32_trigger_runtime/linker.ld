/* Auditable layout corresponding to generate_fixture.py. */
ENTRY(_start)
SECTIONS
{
  . = 0x40200000;
  .text : { *(.text) }
}
