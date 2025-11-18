\copy shareholders(acno, name, phone_number, holdings, address, email, chn, rin, created_at) FROM 'C:\Users\fadebowale\Desktop\APEL-WEBSITE\eunisellreg.csv' WITH (FORMAT csv, HEADER true, DELIMITER ',');
|
v
import this local csv file to the database

