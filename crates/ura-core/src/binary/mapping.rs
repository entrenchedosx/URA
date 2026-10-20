use super::{Analysis, Section};

impl Analysis {
    pub fn executable_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|section| section.executable)
    }

    pub fn section_containing_address(&self, address: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.contains_address(address))
    }

    pub fn code_section_containing_address(&self, address: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.executable && section.contains_address(address))
    }

    pub fn section_containing_file_offset(&self, offset: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.contains_file_offset(offset))
    }

    pub fn address_to_file_offset(&self, address: u64) -> Option<u64> {
        let section = self.section_containing_address(address)?;
        section.file_offset_for_address(address)
    }

    pub fn file_offset_to_address(&self, offset: u64) -> Option<u64> {
        let section = self.section_containing_file_offset(offset)?;
        section.address_for_file_offset(offset)
    }

    pub fn address_to_rva(&self, address: u64) -> Option<u64> {
        address.checked_sub(self.image_base)
    }

    pub fn rva_to_address(&self, rva: u64) -> Option<u64> {
        self.image_base.checked_add(rva)
    }
}
