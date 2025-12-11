import re
import itertools

css = """
@keyframes blink {
  0.00% {
    opacity: 1;
  }
  0.79% {
    opacity: 1;
  }
  0.79% {
    opacity: 1;
  }
  1.57% {
    opacity: 1;
  }
  1.57% {
    opacity: 1;
  }
  2.36% {
    opacity: 1;
  }
  2.36% {
    opacity: 0;
  }
  3.15% {
    opacity: 0;
  }
  3.15% {
    opacity: 1;
  }
  3.94% {
    opacity: 1;
  }
  3.94% {
    opacity: 0;
  }
  4.72% {
    opacity: 0;
  }
  4.72% {
    opacity: 1;
  }
  5.51% {
    opacity: 1;
  }
  5.51% {
    opacity: 1;
  }
  6.30% {
    opacity: 1;
  }
  6.30% {
    opacity: 1;
  }
  7.09% {
    opacity: 1;
  }
  7.09% {
    opacity: 0;
  }
  7.87% {
    opacity: 0;
  }
  7.87% {
    opacity: 1;
  }
  8.66% {
    opacity: 1;
  }
  8.66% {
    opacity: 1;
  }
  9.45% {
    opacity: 1;
  }
  9.45% {
    opacity: 1;
  }
  10.24% {
    opacity: 1;
  }
  10.24% {
    opacity: 0;
  }
  11.02% {
    opacity: 0;
  }
  11.02% {
    opacity: 0;
  }
  11.81% {
    opacity: 0;
  }
  11.81% {
    opacity: 0;
  }
  12.60% {
    opacity: 0;
  }
  12.60% {
    opacity: 1;
  }
  13.39% {
    opacity: 1;
  }
  13.39% {
    opacity: 0;
  }
  14.17% {
    opacity: 0;
  }
  14.17% {
    opacity: 1;
  }
  14.96% {
    opacity: 1;
  }
  14.96% {
    opacity: 1;
  }
  15.75% {
    opacity: 1;
  }
  15.75% {
    opacity: 1;
  }
  16.54% {
    opacity: 1;
  }
  16.54% {
    opacity: 0;
  }
  17.32% {
    opacity: 0;
  }
  17.32% {
    opacity: 1;
  }
  18.11% {
    opacity: 1;
  }
  18.11% {
    opacity: 0;
  }
  18.90% {
    opacity: 0;
  }
  18.90% {
    opacity: 1;
  }
  19.69% {
    opacity: 1;
  }
  19.69% {
    opacity: 0;
  }
  20.47% {
    opacity: 0;
  }
  20.47% {
    opacity: 0;
  }
  21.26% {
    opacity: 0;
  }
  21.26% {
    opacity: 0;
  }
  22.05% {
    opacity: 0;
  }
  22.05% {
    opacity: 1;
  }
  22.83% {
    opacity: 1;
  }
  22.83% {
    opacity: 0;
  }
  23.62% {
    opacity: 0;
  }
  23.62% {
    opacity: 1;
  }
  24.41% {
    opacity: 1;
  }
  24.41% {
    opacity: 0;
  }
  25.20% {
    opacity: 0;
  }
  25.20% {
    opacity: 1;
  }
  25.98% {
    opacity: 1;
  }
  25.98% {
    opacity: 0;
  }
  26.77% {
    opacity: 0;
  }
  26.77% {
    opacity: 1;
  }
  27.56% {
    opacity: 1;
  }
  27.56% {
    opacity: 1;
  }
  28.35% {
    opacity: 1;
  }
  28.35% {
    opacity: 1;
  }
  29.13% {
    opacity: 1;
  }
  29.13% {
    opacity: 0;
  }
  29.92% {
    opacity: 0;
  }
  29.92% {
    opacity: 0;
  }
  30.71% {
    opacity: 0;
  }
  30.71% {
    opacity: 0;
  }
  31.50% {
    opacity: 0;
  }
  31.50% {
    opacity: 1;
  }
  32.28% {
    opacity: 1;
  }
  32.28% {
    opacity: 0;
  }
  33.07% {
    opacity: 0;
  }
  33.07% {
    opacity: 1;
  }
  33.86% {
    opacity: 1;
  }
  33.86% {
    opacity: 0;
  }
  34.65% {
    opacity: 0;
  }
  34.65% {
    opacity: 0;
  }
  35.43% {
    opacity: 0;
  }
  35.43% {
    opacity: 0;
  }
  36.22% {
    opacity: 0;
  }
  36.22% {
    opacity: 1;
  }
  37.01% {
    opacity: 1;
  }
  37.01% {
    opacity: 0;
  }
  37.80% {
    opacity: 0;
  }
  37.80% {
    opacity: 1;
  }
  38.58% {
    opacity: 1;
  }
  38.58% {
    opacity: 0;
  }
  39.37% {
    opacity: 0;
  }
  39.37% {
    opacity: 1;
  }
  40.16% {
    opacity: 1;
  }
  40.16% {
    opacity: 0;
  }
  40.94% {
    opacity: 0;
  }
  40.94% {
    opacity: 0;
  }
  41.73% {
    opacity: 0;
  }
  41.73% {
    opacity: 0;
  }
  42.52% {
    opacity: 0;
  }
  42.52% {
    opacity: 1;
  }
  43.31% {
    opacity: 1;
  }
  43.31% {
    opacity: 0;
  }
  44.09% {
    opacity: 0;
  }
  44.09% {
    opacity: 1;
  }
  44.88% {
    opacity: 1;
  }
  44.88% {
    opacity: 0;
  }
  45.67% {
    opacity: 0;
  }
  45.67% {
    opacity: 1;
  }
  46.46% {
    opacity: 1;
  }
  46.46% {
    opacity: 1;
  }
  47.24% {
    opacity: 1;
  }
  47.24% {
    opacity: 1;
  }
  48.03% {
    opacity: 1;
  }
  48.03% {
    opacity: 0;
  }
  48.82% {
    opacity: 0;
  }
  48.82% {
    opacity: 1;
  }
  49.61% {
    opacity: 1;
  }
  49.61% {
    opacity: 1;
  }
  50.39% {
    opacity: 1;
  }
  50.39% {
    opacity: 1;
  }
  51.18% {
    opacity: 1;
  }
  51.18% {
    opacity: 0;
  }
  51.97% {
    opacity: 0;
  }
  51.97% {
    opacity: 1;
  }
  52.76% {
    opacity: 1;
  }
  52.76% {
    opacity: 1;
  }
  53.54% {
    opacity: 1;
  }
  53.54% {
    opacity: 1;
  }
  54.33% {
    opacity: 1;
  }
  54.33% {
    opacity: 0;
  }
  55.12% {
    opacity: 0;
  }
  55.12% {
    opacity: 0;
  }
  55.91% {
    opacity: 0;
  }
  55.91% {
    opacity: 0;
  }
  56.69% {
    opacity: 0;
  }
  56.69% {
    opacity: 1;
  }
  57.48% {
    opacity: 1;
  }
  57.48% {
    opacity: 1;
  }
  58.27% {
    opacity: 1;
  }
  58.27% {
    opacity: 1;
  }
  59.06% {
    opacity: 1;
  }
  59.06% {
    opacity: 0;
  }
  59.84% {
    opacity: 0;
  }
  59.84% {
    opacity: 1;
  }
  60.63% {
    opacity: 1;
  }
  60.63% {
    opacity: 1;
  }
  61.42% {
    opacity: 1;
  }
  61.42% {
    opacity: 1;
  }
  62.20% {
    opacity: 1;
  }
  62.20% {
    opacity: 0;
  }
  62.99% {
    opacity: 0;
  }
  62.99% {
    opacity: 1;
  }
  63.78% {
    opacity: 1;
  }
  63.78% {
    opacity: 1;
  }
  64.57% {
    opacity: 1;
  }
  64.57% {
    opacity: 1;
  }
  65.35% {
    opacity: 1;
  }
  65.35% {
    opacity: 0;
  }
  66.14% {
    opacity: 0;
  }
  66.14% {
    opacity: 1;
  }
  66.93% {
    opacity: 1;
  }
  66.93% {
    opacity: 1;
  }
  67.72% {
    opacity: 1;
  }
  67.72% {
    opacity: 1;
  }
  68.50% {
    opacity: 1;
  }
  68.50% {
    opacity: 0;
  }
  69.29% {
    opacity: 0;
  }
  69.29% {
    opacity: 1;
  }
  70.08% {
    opacity: 1;
  }
  70.08% {
    opacity: 1;
  }
  70.87% {
    opacity: 1;
  }
  70.87% {
    opacity: 1;
  }
  71.65% {
    opacity: 1;
  }
  71.65% {
    opacity: 0;
  }
  72.44% {
    opacity: 0;
  }
  72.44% {
    opacity: 0;
  }
  73.23% {
    opacity: 0;
  }
  73.23% {
    opacity: 0;
  }
  74.02% {
    opacity: 0;
  }
  74.02% {
    opacity: 1;
  }
  74.80% {
    opacity: 1;
  }
  74.80% {
    opacity: 0;
  }
  75.59% {
    opacity: 0;
  }
  75.59% {
    opacity: 1;
  }
  76.38% {
    opacity: 1;
  }
  76.38% {
    opacity: 1;
  }
  77.17% {
    opacity: 1;
  }
  77.17% {
    opacity: 1;
  }
  77.95% {
    opacity: 1;
  }
  77.95% {
    opacity: 0;
  }
  78.74% {
    opacity: 0;
  }
  78.74% {
    opacity: 1;
  }
  79.53% {
    opacity: 1;
  }
  79.53% {
    opacity: 1;
  }
  80.31% {
    opacity: 1;
  }
  80.31% {
    opacity: 1;
  }
  81.10% {
    opacity: 1;
  }
  81.10% {
    opacity: 0;
  }
  81.89% {
    opacity: 0;
  }
  81.89% {
    opacity: 1;
  }
  82.68% {
    opacity: 1;
  }
  82.68% {
    opacity: 1;
  }
  83.46% {
    opacity: 1;
  }
  83.46% {
    opacity: 1;
  }
  84.25% {
    opacity: 1;
  }
  84.25% {
    opacity: 0;
  }
  85.04% {
    opacity: 0;
  }
  85.04% {
    opacity: 1;
  }
  85.83% {
    opacity: 1;
  }
  85.83% {
    opacity: 1;
  }
  86.61% {
    opacity: 1;
  }
  86.61% {
    opacity: 1;
  }
  87.40% {
    opacity: 1;
  }
  87.40% {
    opacity: 0;
  }
  88.19% {
    opacity: 0;
  }
  88.19% {
    opacity: 0;
  }
  88.98% {
    opacity: 0;
  }
  88.98% {
    opacity: 0;
  }
  89.76% {
    opacity: 0;
  }
  89.76% {
    opacity: 1;
  }
  90.55% {
    opacity: 1;
  }
  90.55% {
    opacity: 0;
  }
  91.34% {
    opacity: 0;
  }
  91.34% {
    opacity: 1;
  }
  92.13% {
    opacity: 1;
  }
  92.13% {
    opacity: 0;
  }
  92.91% {
    opacity: 0;
  }
  92.91% {
    opacity: 1;
  }
  93.70% {
    opacity: 1;
  }
  93.70% {
    opacity: 0;
  }
  94.49% {
    opacity: 0;
  }
  94.49% {
    opacity: 1;
  }
  95.28% {
    opacity: 1;
  }
  95.28% {
    opacity: 1;
  }
  96.06% {
    opacity: 1;
  }
  96.06% {
    opacity: 1;
  }
  96.85% {
    opacity: 1;
  }
  96.85% {
    opacity: 0;
  }
  97.64% {
    opacity: 0;
  }
  97.64% {
    opacity: 1;
  }
  98.43% {
    opacity: 1;
  }
  98.43% {
    opacity: 1;
  }
  99.21% {
    opacity: 1;
  }
  99.21% {
    opacity: 1;
  }
  100.00% {
    opacity: 1;
  }
}
"""

# Extract opacity values
pattern = r'opacity:\s*([01]);'
matches = re.findall(pattern, css)
binary_string = ''.join(matches)

# Group consecutive identical values
groups = [''.join(g) for k, g in itertools.groupby(binary_string)]

# Convert to Morse
morse = []
for group in groups:
    if '1' in group:
        if len(group) >= 4:
            morse.append('-')
        else:
            morse.append('.')
    else:
        if len(group) >= 4:
            morse.append(' ')
morse_str = ''.join(morse)
print(f"Extracted Morse: {morse_str}")

# Morse Code Dictionary
morse_code = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?'
}

morse_parts = morse_str.split(' ')
decoded = ""
for part in morse_parts:
    if part in morse_code:
        decoded += morse_code[part]

print(f"Decoded Message: {decoded}")