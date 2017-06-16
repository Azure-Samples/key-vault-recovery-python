from backup_restore_sample import BackupRestoreSample
from soft_delete_sample import SoftDeleteSample
from key_vault_sample_base import run_all_samples

if __name__ == "__main__":
    run_all_samples([BackupRestoreSample(), SoftDeleteSample()])
