for i in `./listKeys.sh | grep "Alias name:" | awk '{ print $3 }'`;
do
echo Deletando ${i};
./deleteKey.sh ${i};
done
