for i in `ls *.rego | grep -v test`; do
  dir_name="${i%.rego}"    # Strip the .rego extension
  mkdir -p "$dir_name"      # Create the directory
  mv $dir_name*rego "$dir_name"
done