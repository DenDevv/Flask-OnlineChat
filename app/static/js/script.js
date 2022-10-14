document.addEventListener("DOMContentLoaded", () => {
  var elements = [
    ".form",
    ".home-nav-panel",
    ".profile",
    ".home-logo",
    ".home-nav-panel",
    ".wrap"
  ];

  elements.forEach(function(element) {
    try {
      document.querySelector(element).style.animation = "fade 2s";
      document.querySelector(element).style.opacity = "1";
    }
    catch (e) {
        //pass
    };
    
  });

  $(function () {
    $('.chat').scrollTop($('.chat')[0].scrollHeight);
  });
});