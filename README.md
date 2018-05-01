# AddSection
Add a New Section to PE file (x86 only)

# Details

There are a least two methods to add a new section to PE file.

## Method 1: Free sapce

The free space is reside between the section headers and the bytes of first section. We can easily retrieve the pointer of the end of section headers and append a new section header in this region. This require a least `sizeof(IMAGE_SECTION_HEADER)` bytes be free, for now this value is equals to `40` bytes.

## Method 2: Expand the PE headers and adjust the offset

If there has not enough space for one section header, we should expand the size of PE headers. The original size of headers is specified by the `SizeOfHeaders` member of `IMAGE_OPTIONAL_HEADER` structure, as MSDN described, this value must round to the multiply of `FileAligment` field.

After expanded the PE headers, the file offset of the reset of data are changed. We must increase the value of `PointerToRawData` member for each section header.

There may has more offset values that need to increase the offset. But for the smallest changing to make the PE file works normally, this should be safe for us.

# Relation field

- IMAGE_FILE_HEADER->NumberOfSections
- IMAGE_OPTIONAL_HEADER->SizeOfImage
- IMAGE_OPTIONAL_HEADER->SizeOfHeaders
- IMAGE_OPTIONAL_HEADER->CheckSum // For drivers and DLL

P.S.: The `SizeOfImage` is rounds to multiply of `SectionAligment` member, on the other hand, this value is equals to:
```
dwSizeOfImage = AlignSize(lpFinalSectionHdr.VirtualAddress + lpFinalSectionHdr->Misc.VirtualSize, dwSectionAligment);
```

# Todo
- [ ] IA-64 compatibility
- [ ] Fix IMAGE_DEBUG_DIRECTORY
- [ ] Fix IMAGE_SECURITY_DIRECTORY