var gulp = require('gulp'),
    concat = require('gulp-concat'),
    rename = require('gulp-rename'),
    uglify = require('gulp-uglify');

gulp.task('js-fef', function () {
    return gulp.src(['./src/**/*.js'])
        .pipe(concat('SignerDesktopClient.js'))
        .pipe(gulp.dest('dist'))
        .pipe(rename('SignerDesktopClient.min.js'))
        .pipe(uglify())
        .pipe(gulp.dest('dist'));
});

gulp.task('default', ['js-fef'], function () { 

});