Param
(
[string]$FilePath,
[String]$SheetName
)

# Create an Object Excel.Application using Com interface
$objExcel = New-Object -ComObject Excel.Application
$objExcel.displayalerts = $false

# Disable the ‘visible’ property so the document won’t open in excel
$objExcel.Visible = $false

# Open the Excel file and save it in $WorkBook
$WorkBook = $objExcel.Workbooks.Open($FilePath)
#Delete required sheets by looping

$workbook.worksheets.item($SheetName).Delete()

$workbook.Save()
$objExcel.Quit()