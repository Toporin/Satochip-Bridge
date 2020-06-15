# Hook for the mnemonic package: https://pypi.org/project/mnemonic/
from PyInstaller.utils.hooks import collect_data_files
datas = collect_data_files('mnemonic')
