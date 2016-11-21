
$("#enviar").click(function () {
    var id = [];
    $.each($("input[name='arquivo']:checked"), function(){            
    	id.push($(this).val());
    });
    
    $.get("api/token/generate/" + id, function (data) {
        $("#hash").val(data);
        $('#jnlpForm').submit();
        $.blockUI({ message: "Aguardando assinaturas" });
        verificarToken(data);
    });

});


function verificarToken(token){
 	console.warn("token: " + token);

 	var refreshId = setInterval(function(){
 	    $.ajax({ 
 	    	type:"GET",
            cache: false,
            url:  "api/token/validate/" + token,
            success: function(data){
                if (data == 'true') 
                	console.warn(data);
                else {
                	$.unblockUI();
                	clearInterval(refreshId);
                }
            }
 	   });
 	}, 5000);
 	
 	window.setTimeout(function() {
 	    clearInterval(refreshId);
 	    $.unblockUI();
 	}, 60000);
}
