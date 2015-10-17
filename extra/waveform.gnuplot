  set terminal png size 2000,200;
  set output 'waveform.png';

  unset key;
  unset tics;
  unset border;
  set lmargin 0;
  set rmargin 0;
  set tmargin 0.5;
  set bmargin 0.5;

  plot '<cat' binary filetype=bin format='%int16' endian=little array=1:0 with lines;
