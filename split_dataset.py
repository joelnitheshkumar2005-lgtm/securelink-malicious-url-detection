
import os
import csv

def split_csv(source_filepath, dest_folder, lines_per_file=100000):
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    
    with open(source_filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        
        file_count = 1
        current_lines = 0
        current_out_writer = None
        current_out_file = None
        
        def start_new_file(count):
            nonlocal current_out_writer, current_out_file
            if current_out_file:
                current_out_file.close()
            
            filename = f'dataset_part_{count}.csv'
            filepath = os.path.join(dest_folder, filename)
            current_out_file = open(filepath, 'w', newline='', encoding='utf-8')
            current_out_writer = csv.writer(current_out_file)
            if header:
                current_out_writer.writerow(header)
            print(f"Created {filename}")
            return count + 1

        file_count = start_new_file(file_count)
        
        for row in reader:
            current_out_writer.writerow(row)
            current_lines += 1
            if current_lines >= lines_per_file:
                file_count = start_new_file(file_count)
                current_lines = 0
        
        if current_out_file:
            current_out_file.close()
            
    print("Splitting complete.")

if __name__ == "__main__":
    split_csv(r'c:\Users\JOEL\.gemini\antigravity\scratch\securelink\dataset\dataset.csv', 
              r'c:\Users\JOEL\.gemini\antigravity\scratch\securelink\dataset')
