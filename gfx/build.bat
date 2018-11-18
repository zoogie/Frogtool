magick convert filein.png -channel R -separate r.png
magick convert filein.png -channel G -separate g.png
magick convert filein.png -channel B -separate b.png
magick convert b.png g.png r.png -combine -colorspace RGB -rotate 90 fileOut.rgb
cp fileOut.rgb ../data/superfrog.bin
pause