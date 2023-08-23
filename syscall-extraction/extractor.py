import angr

def extract(file_path):
    proj = angr.Project(file_path, load_options={"auto_load_libs": False})

    # Start with the binary entry point
    block = proj.factory.block(proj.entry)
    print(block)

    return proj