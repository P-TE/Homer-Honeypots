function Delete(elem){
var id = elem.id; 
var name = elem.name;
var xhr = new XMLHttpRequest();
var host = document.getElementsByName("host")[0].value;
xhr.open('POST', "http://"+host+"/install", true);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send("name="+name+"&id="+id+"&submit=delete");
}


function valueChanged(elem){
    var a = document.getElementsByClassName("cache");
    for (i=0; i<a.length; i++){
      a[i].style.display='none';
    }
    if (elem.value != "--Choix--"){
        document.getElementById(elem.value).style.display = "block";
    }
    if (elem.value == "--Choix--"){
        document.getElementById('pre_terminer').style.display = "block";
    }
    
}

function validateIpAndPort(input) {
    var parts = input.split(":");
    var ip = parts[0].split(".");
    var port = parts[1];
    return validateNum(port, 1, 65535) && ip.length == 4 && ip.every(function (segment) {
        return validateNum(segment, 0, 255);
    });
}

function validateNum(input, min, max) {
    var num = +input;
    return num >= min && num <= max && input === num.toString();
}
function doSomething(elem){
var id = elem.id;
var ip = document.getElementsByName(id)[0].value;

if(validateIpAndPort(ip)){  
  var xhr = new XMLHttpRequest();
  var host = document.getElementsByName("host")[0].value;
  xhr.open('POST', "http://"+host+"/api", true);
  xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  xhr.send("ip="+ip);
   
  xhr.onreadystatechange = processRequest;
  function processRequest(e) {
      if (xhr.readyState == 4 && xhr.status == 200) {
          var response = xhr.responseText;
          if(response == '0'){
            // console.log(elem)
            //elem.style.backgroundColor = "#ea1414";
            document.getElementById(id).innerText = "NOK";
            document.getElementById(id).style.background = "red";
            document.getElementById('end'+id).disabled = 1;
          }
          if(response == '1'){
            document.getElementById(id).innerText = "OK";
            document.getElementById(id).style.background = "#7ace4c";
            document.getElementById('end'+id).disabled = 0;
          }
      }
  }
}  
else  
 {  
  $(".alert").alert('close');
  document.getElementById(id).innerText = "Invalid";
  document.getElementById(id).style.background = "red";
  document.getElementById('end'+id).disabled = 1;    
 }  


}