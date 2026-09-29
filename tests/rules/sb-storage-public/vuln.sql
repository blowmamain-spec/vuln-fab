insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);  -- vuln: sb-storage-public
insert into storage.buckets (id, name, public) values ('kyc-documents', 'kyc-documents', true);  -- vuln: sb-storage-public
