# Vhdx-rs
a parsing library for reading the vhdx file format.

Current output:

```json
{
    Vhdx {
        header: Header {
            fti: FileTypeIdentifier {
                signature: Vhdxfile,
                creator: "Microsoft Windows 10.0.19045.0",
            },
            header_1: Headers {
                signature: Head,
                checksum: 2148003692,
                seq_number: 4,
                file_write_guid: b365e0cc-f1aa-4bd8-9c8d-1609d938b5ec,
                data_write_guid: 76cae359-f9ef-45ab-ad4a-77daaecef617,
                log_guid: 00000000-0000-0000-0000-000000000000,
                log_version: 0,
                version: 1,
                log_length: 1048576,
                log_offset: 1048576,
            },
            header_2: Headers {
                signature: Head,
                checksum: 50295579,
                seq_number: 5,
                file_write_guid: b365e0cc-f1aa-4bd8-9c8d-1609d938b5ec,
                data_write_guid: 76cae359-f9ef-45ab-ad4a-77daaecef617,
                log_guid: 00000000-0000-0000-0000-000000000000,
                log_version: 0,
                version: 1,
                log_length: 1048576,
                log_offset: 1048576,
            },
            rt_1: RTHeader {
                signature: Regi,
                checksum: 3328937134,
                entry_count: 2,
                table_entries: [
                    RTEntry {
                        guid: 2dc27766-f623-4200-9d64-115e9bfd4a08,
                        file_offset: 3145728,
                        length: 1048576,
                        required: true,
                    },
                    RTEntry {
                        guid: 8b7ca206-4790-4b9a-b8fe-575f050f886e,
                        file_offset: 2097152,
                        length: 1048576,
                        required: true,
                    },
                ],
            },
            rt_2: RTHeader {
                signature: Regi,
                checksum: 3328937134,
                entry_count: 2,
                table_entries: [
                    RTEntry {
                        guid: 2dc27766-f623-4200-9d64-115e9bfd4a08,
                        file_offset: 3145728,
                        length: 1048576,
                        required: true,
                    },
                    RTEntry {
                        guid: 8b7ca206-4790-4b9a-b8fe-575f050f886e,
                        file_offset: 2097152,
                        length: 1048576,
                        required: true,
                    },
                ],
            },
        },
        log: Log {
            log_entries: [
                LogEntry {
                    header: Header {
                        signature: "loge",
                        checksum: 3925684412,
                        entry_length: 4096,
                        tail: 0,
                        seq_number: 3902458203083041933,
                        descript_count: 0,
                        log_guid: 020a46dd-b41d-134d-ad70-dc3093afd5c2,
                        flushed_file_offset: 8388608,
                        last_file_offset: 8388608,
                    },
                    descriptors: [],
                },
                LogEntry {
                    header: Header {
                        signature: "loge",
                        checksum: 2536420826,
                        entry_length: 73728,
                        tail: 4096,
                        seq_number: 3902458203083041934,
                        descript_count: 17,
                        log_guid: 020a46dd-b41d-134d-ad70-dc3093afd5c2,
                        flushed_file_offset: 4194304,
                        last_file_offset: 8388608,
                    },
                    descriptors: [
                        Data {
                            signature: Desc,
                            file_offset: 3145728,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2097152,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2101248,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2105344,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2109440,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2113536,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2117632,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2121728,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2125824,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2129920,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2134016,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2138112,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2142208,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2146304,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2150400,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2154496,
                            seq_number: 3902458203083041934,
                        },
                        Data {
                            signature: Desc,
                            file_offset: 2158592,
                            seq_number: 3902458203083041934,
                        },
                    ],
                },
            ],
        },
        meta_data: MetaData {
            signature: MetaData,
            entry_count: 5,
            file_parameters: FileParameters {
                block_size: 2097152,
                leave_block_allocated: false,
                has_parent: false,
            },
            virtual_disk_size: 4194304,
            virtual_disk_id: 76cae359-f9ef-45ab-ad4a-77daaecef617,
            logical_sector_size: Sector512,
            physical_sector_size: Sector512,
            chunk_ratio: 2048,
            payload_blocks_count: 2,
            sector_bitmaps_blocks_count: 1,
            total_bat_entries_fixed_dynamic: 2,
            total_bat_entries_differencing: 2049,
            entries: {
                caa16737-fa36-4d43-b3b6-33f0aa44e76b: Entry {
                    item_id: caa16737-fa36-4d43-b3b6-33f0aa44e76b,
                    offset: 65536,
                    length: 8,
                    is_user: false,
                    is_virtual_disk: false,
                    is_required: true,
                },
                8141bf1d-a96f-4709-ba47-f233a8faab5f: Entry {
                    item_id: 8141bf1d-a96f-4709-ba47-f233a8faab5f,
                    offset: 65552,
                    length: 4,
                    is_user: false,
                    is_virtual_disk: true,
                    is_required: true,
                },
                2fa54224-cd1b-4876-b211-5dbed83bf4b8: Entry {
                    item_id: 2fa54224-cd1b-4876-b211-5dbed83bf4b8,
                    offset: 65544,
                    length: 8,
                    is_user: false,
                    is_virtual_disk: true,
                    is_required: true,
                },
                cda348c7-445d-4471-9cc9-e9885251c556: Entry {
                    item_id: cda348c7-445d-4471-9cc9-e9885251c556,
                    offset: 65556,
                    length: 4,
                    is_user: false,
                    is_virtual_disk: true,
                    is_required: true,
                },
                beca12ab-b2e6-4523-93ef-c309e000c746: Entry {
                    item_id: beca12ab-b2e6-4523-93ef-c309e000c746,
                    offset: 65560,
                    length: 16,
                    is_user: false,
                    is_virtual_disk: true,
                    is_required: true,
                },
            },
        },
        bat_table: [
            BatEntry {
                state: PayLoadBlockFullyPresent,
                file_offset_mb: 4,
            },
            BatEntry {
                state: PayLoadBlockFullyPresent,
                file_offset_mb: 6,
            },
        ],
    }
}
```
