def sort_dir_entry(entry):
    # Key for sorted to sort DirEntry objects
    if entry.is_file():
        # This ensures that directories always get transmitted first and file second.
        return f'1{entry.name}'
    return f'0{entry.name}'
